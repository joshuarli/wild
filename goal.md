Make Wild the fastest correct and most memory-efficient macOS Mach-O linker for real production
workloads.

Work benchmark-first. Do not optimize from intuition: before each change, capture the exact final linker invocation, measure it with Wild’s `--time=json`, add or retain a regression, then rerun the full benchmark matrix.

Context is in BENCHMARKING.md.

Primary targets:

- Cold direct final-link replays without a usable cache: Wild ≤ 0.85× Apple ld64 median wall
  time, with no tracked workload slower than Apple.
- Cold release Cargo workspace builds: Wild ≤ 0.95× Apple median wall time, with no tracked
  workload above 1.00×. Record wrapper arguments and build phases; a direct final-link replay is
  the authoritative linker comparison.
- Cache-eligible incremental final links: Wild ≤ 0.60× Apple median wall time, with no tracked
  workload above 0.70×. The stretch target is ≤ 0.50× median and ≤ 0.60× on every workload.
- Peak RSS: Wild ≤ 0.75× Apple median peak RSS and ≤ 0.90× on every tracked final-link replay.
  Measure this in the separate, comparable resource batch—not from wall-time runs or Cargo's
  process tree.
- Final outputs: record and compare Wild's apparent and allocated output bytes against Apple's for
  equivalent inputs and link options. Output growth above 1.05× Apple's needs a documented format
  or toolchain reason, a supported cache topology, or a verified incremental direct-link gain of
  at least 15%; otherwise treat it as a regression. Do not trade peak-RSS regressions this way.
- Never trade a cold or incremental speed win for an unexplained memory regression. A change
  that increases peak RSS by more than 3% on a tracked workload must retain a direct-link win of
  at least 15% or add a documented supported incremental topology.
- Never accept a cache “hit” unless it is proven to use the fast path and the resulting Mach-O
  passes codesign verification and runtime/integration checks.

Benchmark at least:

1. `~/d/e` — fast iteration workload.
2. `~/d/pi-agent-core-rs` — full release workspace, `pi-agent`, and `pi-agent-headless`.
3. A proc-macro dylib workload.
4. A native/C++ or staticlib workload.
5. A large Rust archive/LTO workload.

Use the generic stdlib-Python benchmark runner and checked-in workload manifests. Pin Cargo to:

    /opt/homebrew/opt/rustup/bin/cargo +nightly-2026-07-24

Measure and report separately:

- Signoff uses at least five interleaved Apple ld64/Wild sample pairs with alternating linker
  order. The per-linker medians remain the pass/fail statistic; also report every paired ratio
  and its median to expose thermal, cache, and host-load drift rather than mistaking it for a
  linker regression.
- cold Cargo workspace wall time;
- Cargo incremental wall time;
- direct final-link replay wall time;
- Wild phase timings from `--time=json`;
- cache-hit/miss rate and miss reasons;
- median user CPU, system CPU, and peak RSS for Wild and Apple ld64 from a separate resource
  batch using the same saved inputs and linker verification;
- final-output apparent/allocated bytes, persistent incremental-cache apparent/allocated bytes,
  cache bytes per final-output byte, and peak transient working-directory apparent/allocated
  bytes from the separate resource batch. The transient value is an observed lower bound from
  5 ms polling and excludes both the prepared and published steady-state states. Never present
  this lower bound as proof of a transient-disk upper bound;
- Mach-O validation, codesign, and runtime checks.

Disk is a measured trade-off, not a blanket cache-growth prohibition. Track and compare Wild and
Apple final-output bytes, and retain the cache's persistent image/sidecars and peak temporary
footprint on every incremental result. For ordinary cache topologies, persistent cache bytes
should remain ≤ 2.00× the final-output bytes; any exception needs a documented cache-hit topology
or at least a 15% direct-link improvement. An optimization that stages more than 0.25× the final
output as observed transient working-directory bytes needs the same justification. Because the
5 ms value is a lower bound, also explain temporary-file lifetime and cleanup; do not use a zero
sample as evidence that no temporary bytes were used.

Prioritize, in order:

1. Broaden verified incremental cache-hit coverage for local layout changes and a small bounded
   set of independently validated direct-object changes, but only where captured workload traces
   show repeated misses. Reject overlapping patches and unsupported topology before mutating an
   output.
2. Remove repeated large-Rust-workload costs in input loading, archive indexing, symbol
   resolution, GC traversal, and relocation/copy work.
3. Improve cache-hit writer, chained-fixup, unwind, UUID, and signing costs only when phase
   timings show a net path to at least a 10% direct-link win after memory and disk costs.

Keep every optimization fail-closed: unsupported topology changes, changed exports/imports, changed dylibs/archives, or unverifiable input state must perform a normal full link. Do not weaken correctness checks, skip signatures, reuse exact outputs, or alter benchmark ordering to improve a result.

For each completed change, report:

- the bottleneck identified;
- baseline versus after medians and ratios;
- baseline versus after peak RSS and disk-footprint medians/ratios when the change can affect
  allocation, mapping, caching, or output staging;
- exact workloads and toolchain;
- cache-hit evidence where applicable;
- tests run;
- remaining limiting phase and the next proposed experiment.
