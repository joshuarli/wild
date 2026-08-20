use crate::args::CounterKind;

pub(crate) struct CounterReading {
    pub(crate) kind: CounterKind,
    pub(crate) value: u64,
}

pub(crate) struct CounterList {
    counters: Vec<(CounterKind, perf_event::Counter)>,
}

impl CounterList {
    pub(crate) fn from_kinds(opts: &[CounterKind]) -> Self {
        let counters = opts
            .iter()
            .filter_map(|kind| {
                perf_event::Builder::new()
                    .inherit(true)
                    .kind(counter_to_perf_event(*kind))
                    .build()
                    .ok()
                    .map(|counter| (*kind, counter))
            })
            .collect();

        CounterList { counters }
    }

    pub(crate) fn start(&mut self) {
        for (_, counter) in &mut self.counters {
            let _ = counter.reset();
            let _ = counter.enable();
        }
    }

    pub(crate) fn disable_and_read(&mut self) -> Vec<CounterReading> {
        self.counters
            .iter_mut()
            .filter_map(|(kind, counter)| {
                counter
                    .disable()
                    .ok()
                    .and_then(|()| counter.read().ok())
                    .map(|value| CounterReading { kind: *kind, value })
            })
            .collect()
    }
}

fn counter_to_perf_event(kind: CounterKind) -> perf_event::events::Event {
    match kind {
        CounterKind::Cycles => perf_event::events::Hardware::CPU_CYCLES.into(),
        CounterKind::Instructions => perf_event::events::Hardware::INSTRUCTIONS.into(),
        CounterKind::CacheMisses => perf_event::events::Hardware::CACHE_MISSES.into(),
        CounterKind::BranchMisses => perf_event::events::Hardware::BRANCH_MISSES.into(),
        CounterKind::PageFaults => perf_event::events::Software::PAGE_FAULTS.into(),
        CounterKind::PageFaultsMinor => perf_event::events::Software::PAGE_FAULTS_MIN.into(),
        CounterKind::PageFaultsMajor => perf_event::events::Software::PAGE_FAULTS_MAJ.into(),
        CounterKind::L1dRead => perf_event::events::Cache {
            which: perf_event::events::WhichCache::L1D,
            operation: perf_event::events::CacheOp::READ,
            result: perf_event::events::CacheResult::ACCESS,
        }
        .into(),
        CounterKind::L1dMiss => perf_event::events::Cache {
            which: perf_event::events::WhichCache::L1D,
            operation: perf_event::events::CacheOp::READ,
            result: perf_event::events::CacheResult::MISS,
        }
        .into(),
    }
}
