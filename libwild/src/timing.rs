//! Code for reporting how long each phase of linking takes when the --time argument is supplied.

#[cfg(test)]
use crate::args::CounterKind;
use crate::args::TimingOptions;
use crate::args::TimingOutput;
use crate::env;
use crate::error::AlreadyInitialised;
use crate::error::Result;
use crate::perf::CounterList;
use crate::perf::CounterReading;
use anyhow::Context;
use anyhow::anyhow;
use crossbeam_queue::ArrayQueue;
use std::fmt::Display;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use tracing::field::Visit;

const PERFETTO_ENV_VAR: &str = "WILD_PERFETTO_OUT";

pub fn setup() -> Result {
    if perfetto_output_file().is_some() {
        perfetto_recorder::start().map_err(
            |_: perfetto_recorder::TracingDisabledAtBuildTime| {
                anyhow!(
                    "{PERFETTO_ENV_VAR} was set, but wild was built without --features perfetto"
                )
            },
        )?;
    }
    Ok(())
}

#[macro_export]
macro_rules! timing_guard {
    ($($args:tt)*) => {
        (tracing::info_span!($($args)*).entered(), perfetto_recorder::start_span!($($args)*))
    };
}

#[macro_export]
macro_rules! timing_phase {
    ($($args:tt)*) => {
        let _guard = $crate::timing_guard!($($args)*);
    };
}

/// More verbose timing instrumentation that by default doesn't show up in the output of --time.
/// Suitable for use from threads other than main.
#[macro_export]
macro_rules! verbose_timing_phase {
    ($($args:tt)*) => {
        perfetto_recorder::scope!($($args)*);
    };
}

struct TimingLayer {
    counter_pool: Option<ArrayQueue<CounterList>>,
    output: TimingOutput,
    output_path: String,
}

struct Data {
    start: Instant,
    child_count: u32,
    attributes_string: String,
    counters: Option<CounterList>,
}

#[derive(Default)]
pub struct ValuesFormatter {
    out: String,
}

impl ValuesFormatter {
    fn finish(mut self) -> String {
        if !self.out.is_empty() {
            self.out.push(']');
        }
        self.out
    }
}

impl Visit for ValuesFormatter {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;

        if self.out.is_empty() {
            write!(&mut self.out, " [").unwrap();
        } else {
            write!(&mut self.out, ", ").unwrap();
        }
        match field.name() {
            "message" => {
                write!(&mut self.out, "{value:?}").unwrap();
            }
            name => {
                write!(&mut self.out, "{name}={value:?}").unwrap();
            }
        }
    }
}

impl<S> tracing_subscriber::Layer<S> for TimingLayer
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::INFO)
    }

    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<S>,
    ) {
        if *attributes.metadata().level() > tracing::Level::INFO {
            return;
        }
        let span = ctx.span(id).expect("valid span ID");

        let mut formatted = ValuesFormatter::default();
        attributes.values().record(&mut formatted);

        let counters = self.counter_pool.as_ref().and_then(|l| l.pop());

        span.extensions_mut().insert(Data {
            start: Instant::now(),
            counters,
            child_count: 0,
            attributes_string: formatted.finish(),
        });
    }

    fn on_enter(&self, id: &tracing::span::Id, ctx: tracing_subscriber::layer::Context<S>) {
        let span = ctx.span(id).expect("valid span ID");
        if let Some(data) = span.extensions_mut().get_mut::<Data>() {
            data.start = Instant::now();
            if let Some(counters) = data.counters.as_mut() {
                counters.start();
            }
        }
    }

    fn on_close(&self, id: tracing::span::Id, ctx: tracing_subscriber::layer::Context<S>) {
        let span = ctx.span(&id).expect("valid span ID");
        let metadata = span.metadata();
        if *metadata.level() > tracing::Level::INFO {
            return;
        }

        let parent_child_count = span
            .parent()
            .and_then(|parent| {
                parent
                    .extensions_mut()
                    .get_mut::<Data>()
                    .map(|parent_data| {
                        parent_data.child_count += 1;
                        parent_data.child_count
                    })
            })
            .unwrap_or(0);

        if let Some(data) = span.extensions_mut().get_mut::<Data>() {
            let scope_depth = span.scope().count() - 1;
            let name = metadata.name();
            let wall = data.start.elapsed();

            let mut counters = data.counters.take();

            let counter_values = counters
                .as_mut()
                .map(|c| c.disable_and_read())
                .unwrap_or_default();

            if let Some(counters) = counters
                && let Some(pool) = self.counter_pool.as_ref()
            {
                let _ = pool.push(counters);
            }

            let reading = Reading {
                wall,
                counter_values,
            };

            let indent = Indent {
                scope_depth,
                child_count: data.child_count,
                parent_child_count,
            };

            match self.output {
                TimingOutput::Text => {
                    println!("{indent}{reading} {name}{}", data.attributes_string);
                }
                // JSON is designed for repeatable benchmark analysis. Emitting every inner
                // span is self-defeating for links with many live atoms: formatting thousands
                // of JSON Lines can dominate the thing being measured. Keep the existing text
                // tree exhaustive for interactive diagnosis, while JSON emits a fixed set of
                // link-critical phases that is stable enough for tools to compare.
                TimingOutput::Json if should_emit_json_phase(name) => {
                    print_json_phase(&self.output_path, name, &reading);
                }
                TimingOutput::Json => {}
            }
        }
    }
}

pub(crate) fn init_tracing(
    options: &TimingOptions,
    output_path: &std::path::Path,
) -> Result<(), AlreadyInitialised> {
    use tracing_subscriber::prelude::*;

    let mut counter_pool = None;

    if !options.counters.is_empty() {
        // Our pool size limits the depth of nested measurements. At the time of writing, we don't
        // have more than 4 levels. Note, we need to create all counters now and can't create more
        // on-demand, since once our worker threads are started, any newly created counters won't
        // apply to them.
        let pool_size = 5;

        let pool = ArrayQueue::new(pool_size);
        for _ in 0..pool_size {
            let _ = pool.push(CounterList::from_kinds(&options.counters));
        }

        counter_pool = Some(pool);
    }

    let layer = TimingLayer {
        counter_pool,
        output: options.output,
        output_path: output_path.to_string_lossy().into_owned(),
    };

    let subscriber = tracing_subscriber::Registry::default().with(layer);
    tracing::subscriber::set_global_default(subscriber).map_err(|_| AlreadyInitialised)
}

/// Whether `--time=json` emits this completed phase.
///
/// Keep this deliberately small. The names form a useful, link-format-neutral summary, with a
/// handful of Mach-O-specific writer and cache phases where our ARM64 benchmark needs more
/// resolution. The human-readable `--time` output remains the exhaustive phase tree.
fn should_emit_json_phase(name: &str) -> bool {
    matches!(
        name,
        "Link"
            | "Parse args"
            | "Open input files"
            | "Load inputs into symbol DB"
            | "Layout"
            | "Traverse reference graph"
            | "Write output file"
            | "Write data to file"
            | "Copy Mach-O object data"
            | "Write Mach-O dynamic tables"
            | "Write Mach-O unwind tables"
            | "Build Mach-O chained fixups"
            | "Hash Mach-O UUID"
            | "Hash Mach-O code signature"
            | "Try Mach-O stable-layout cache"
            | "Mach-O stable-layout cache: read manifest"
            | "Mach-O stable-layout cache: decode manifest"
            | "Mach-O stable-layout cache: verify arguments"
            | "Mach-O stable-layout cache: read image state"
            | "Mach-O stable-layout cache: decode image state"
            | "Mach-O stable-layout cache: verify image state"
            | "Mach-O stable-layout cache: verify current output lineage"
            | "Mach-O stable-layout cache: fingerprint inputs"
            | "Mach-O stable-layout cache: select changed inputs"
            | "Mach-O stable-layout cache: find cached object records"
            | "Mach-O stable-layout cache: validate changed object snapshots"
            | "Mach-O stable-layout cache: read and verify baseline image"
            | "Mach-O stable-layout cache: prepare rustc archive debug paths"
            | "Mach-O stable-layout cache: patch and sign"
            | "Mach-O stable-layout cache: hash patched normalized output"
            | "Mach-O stable-layout cache: recheck input metadata"
            | "Mach-O stable-layout cache: atomically replace output"
            | "Mach-O stable-layout cache: atomically update sidecars"
    )
}

/// Writes one selected `--time=json` record. The field names and their order are part of the
/// command-line contract: downstream tools may parse these JSON Lines without scraping the
/// human timing tree.
fn print_json_phase(output_path: &str, name: &str, reading: &Reading) {
    println!("{}", json_phase_record(output_path, name, reading));
}

fn json_phase_record(output_path: &str, name: &str, reading: &Reading) -> String {
    use std::fmt::Write as _;

    let mut line = String::from("{\"schema_version\":1,\"event\":\"phase\",\"output\":");
    write_json_string(&mut line, output_path).unwrap();
    line.push_str(",\"name\":");
    write_json_string(&mut line, name).unwrap();
    write!(
        line,
        ",\"wall_time_ns\":{},\"counters\":[",
        reading.wall.as_nanos()
    )
    .unwrap();
    for (index, value) in reading.counter_values.iter().enumerate() {
        if index != 0 {
            line.push(',');
        }
        write!(
            line,
            "{{\"name\":\"{}\",\"value\":{}}}",
            value.kind.name(),
            value.value
        )
        .unwrap();
    }
    line.push_str("]}");
    line
}

/// Escapes a string according to JSON's string grammar without bringing a serialization
/// dependency into the linker's hot dependency graph.
fn write_json_string(out: &mut String, value: &str) -> std::fmt::Result {
    use std::fmt::Write as _;

    out.push('\"');
    for character in value.chars() {
        match character {
            '\"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if character.is_control() => write!(out, "\\u{:04x}", character as u32)?,
            character => out.push(character),
        }
    }
    out.push('\"');
    Ok(())
}

struct Reading {
    wall: Duration,
    counter_values: Vec<CounterReading>,
}

struct Indent {
    scope_depth: usize,
    parent_child_count: u32,
    child_count: u32,
}

impl Display for Indent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.scope_depth == 0 {
            write!(f, "└─")?;
            return Ok(());
        }
        for _ in 0..self.scope_depth - 1 {
            write!(f, "│ ")?;
        }
        if self.parent_child_count >= 2 {
            write!(f, "├─")?;
        } else {
            write!(f, "┌─")?;
        }
        if self.child_count > 0 {
            write!(f, "┴─")?;
        } else {
            write!(f, "──")?;
        }
        Ok(())
    }
}

impl Display for Reading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ms = self.wall.as_secs_f64() * 1000.0;
        write!(f, "{ms:>8.2}")?;

        if !self.counter_values.is_empty() {
            write!(f, " (")?;
            let mut first = true;
            for value in &self.counter_values {
                if first {
                    first = false;
                } else {
                    write!(f, ", ")?;
                }
                write!(f, "{}", value.value)?;
            }
            write!(f, ")")?;
        }

        Ok(())
    }
}

fn perfetto_output_file() -> Option<PathBuf> {
    env::var(PERFETTO_ENV_VAR).ok().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_string_uses_json_escapes() {
        let mut out = String::new();
        write_json_string(&mut out, "Mach-O \"phase\"\\\n\u{0008}").unwrap();
        assert_eq!(out, "\"Mach-O \\\"phase\\\"\\\\\\n\\b\"");
    }

    #[test]
    fn json_phase_record_has_stable_fields() {
        let reading = Reading {
            wall: Duration::from_nanos(42),
            counter_values: vec![CounterReading {
                kind: CounterKind::Cycles,
                value: 7,
            }],
        };

        assert_eq!(
            json_phase_record("target/release/pi-agent-headless", "Hash Mach-O UUID", &reading),
            "{\"schema_version\":1,\"event\":\"phase\",\"output\":\"target/release/pi-agent-headless\",\"name\":\"Hash Mach-O UUID\",\"wall_time_ns\":42,\"counters\":[{\"name\":\"cycles\",\"value\":7}]}"
        );
    }

    #[test]
    fn json_timing_is_bounded_to_link_critical_phases() {
        assert!(should_emit_json_phase("Link"));
        assert!(should_emit_json_phase("Traverse reference graph"));
        assert!(should_emit_json_phase("Try Mach-O stable-layout cache"));
        assert!(should_emit_json_phase(
            "Mach-O stable-layout cache: verify current output lineage"
        ));
        assert!(should_emit_json_phase(
            "Mach-O stable-layout cache: hash patched normalized output"
        ));
        assert!(!should_emit_json_phase("Record Mach-O live atom"));
        assert!(!should_emit_json_phase("Write object"));
    }
}

pub(crate) fn finalise_perfetto_trace() -> Result {
    let Some(path) = perfetto_output_file() else {
        return Ok(());
    };

    let mut trace = perfetto_recorder::TraceBuilder::new()?;

    trace.process_thread_data(&perfetto_recorder::ThreadTraceData::take_current_thread());
    let trace = Mutex::new(trace);

    rayon::in_place_scope(|scope| {
        scope.spawn_broadcast(|_scope, _ctx| {
            trace
                .lock()
                .unwrap()
                .process_thread_data(&perfetto_recorder::ThreadTraceData::take_current_thread());
        });
    });

    trace
        .into_inner()
        .unwrap()
        .write_to_file(&path)
        .with_context(|| format!("Failed to write perfetto trace to `{}`", path.display()))?;

    Ok(())
}
