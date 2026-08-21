Make Wild the fastest correct and most memory-efficient ARM64 Mach-O linker for real Rust workloads.

Work benchmark-first. Do not optimize from intuition: before each change, capture the exact final linker invocation, measure it with Wild’s `--time=json`, add or retain a regression, then rerun the full benchmark matrix.

Context is in BENCHMARKING.md.

Primary targets:

- Cold release workspace builds: Wild ≤ 1.00× Apple ld64 median wall time.
- Incremental final links: Wild ≤ 0.75× Apple ld64 median wall time for cache-eligible
  changed-object links.
- Stretch goal: Wild ≤ 0.60× Apple ld64 for cache-eligible changed-object links.
- Peak RSS: Wild ≤ 1.00× Apple ld64 median peak RSS on every tracked final-link replay, with no
  workload above 1.10× Apple. This is measured in the separate, comparable resource batch—not
  inferred from wall-time runs or Cargo's process tree.
- Never trade cold performance for incremental wins: cold must remain ≤ 1.05× Apple on every tracked workload.
- Never trade a speed win for an unexplained peak-RSS regression. A change that increases peak
  RSS by more than 5% on a tracked workload must retain a direct-link win of at least 10% or add
  a documented supported incremental topology.
- Never accept a cache “hit” unless it is proven to use the fast path and the resulting ARM64 Mach-O passes codesign verification and runtime/integration checks.

Benchmark at least:

1. `~/d/e` — fast iteration workload.
2. `~/d/pi-agent-core-rs` — full release workspace, `pi-agent`, and `pi-agent-headless`.
3. A proc-macro dylib workload.
4. A native/C++ or staticlib workload.
5. A large Rust archive/LTO workload.

Use the generic stdlib-Python benchmark runner and checked-in workload manifests. Pin Cargo to:

    /opt/homebrew/opt/rustup/bin/cargo +nightly-2026-07-24

Measure and report separately:

- cold Cargo workspace wall time;
- Cargo incremental wall time;
- direct final-link replay wall time;
- Wild phase timings from `--time=json`;
- cache-hit/miss rate and miss reasons;
- median user CPU, system CPU, and peak RSS for Wild and Apple ld64 from a separate resource
  batch using the same saved inputs and linker verification;
- final-output apparent/allocated bytes, persistent incremental-cache apparent/allocated bytes,
  and cache bytes per final-output byte; add peak transient working-directory bytes once the
  generic runner can sample it without perturbing link timing;
- ARM64 Mach-O validation, codesign, and runtime checks.

Disk is a measured trade-off, not a blanket cache-growth prohibition. Retain and compare the
cache's persistent image/sidecars and its peak temporary footprint on every incremental result.
Storage growth is acceptable when it enables a new safe cache-hit topology or produces a measured
direct-link improvement of at least 10%; explain the byte delta and why the gain is worth it.

Prioritize, in order:

1. Broaden stable-layout incremental linking beyond same-size edits:
   support safe local code-size/symbol-offset changes while preserving global layout when possible.
2. Remove repeated large-Rust-workload costs in input loading, archive indexing, symbol resolution, GC traversal, and relocation/copy work.
3. Improve writer, chained-fixup, unwind, UUID, and signing costs only when measurements show they dominate.

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
