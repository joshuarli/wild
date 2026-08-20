Make Wild the fastest correct ARM64 Mach-O linker for real Rust workloads.

Work benchmark-first. Do not optimize from intuition: before each change, capture the exact final linker invocation, measure it with Wild’s `--time=json`, add or retain a regression, then rerun the full benchmark matrix.

Context is in BENCHMARKING.md.

Primary targets:

- Cold release workspace builds: Wild ≤ 1.00× Apple ld64 median wall time.
- Incremental final links: Wild ≤ 0.50× Apple ld64 median wall time.
- Stretch goal: Wild ≤ 0.35× Apple ld64 for cache-eligible changed-object links.
- Never trade cold performance for incremental wins: cold must remain ≤ 1.05× Apple on every tracked workload.
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
- output size, ARM64 Mach-O validation, codesign, and runtime checks.

Prioritize, in order:

1. Broaden stable-layout incremental linking beyond same-size edits:
   support safe local code-size/symbol-offset changes while preserving global layout when possible.
2. Remove repeated large-Rust-workload costs in input loading, archive indexing, symbol resolution, GC traversal, and relocation/copy work.
3. Improve writer, chained-fixup, unwind, UUID, and signing costs only when measurements show they dominate.

Keep every optimization fail-closed: unsupported topology changes, changed exports/imports, changed dylibs/archives, or unverifiable input state must perform a normal full link. Do not weaken correctness checks, skip signatures, reuse exact outputs, or alter benchmark ordering to improve a result.

For each completed change, report:

- the bottleneck identified;
- baseline versus after medians and ratios;
- exact workloads and toolchain;
- cache-hit evidence where applicable;
- tests run;
- remaining limiting phase and the next proposed experiment.

## Completed macOS finish line

The current ARM64 qualification is deliberately bounded. Keep the limitations and evidence in
[`docs/macho-rust-status.md`](docs/macho-rust-status.md), and do not advertise broad macOS support
until the ARM64 expansion is complete.

ARM64 expansion completed with the bounded evidence and limitations recorded in
[`docs/macho-rust-status.md`](docs/macho-rust-status.md):

- [x] Broaden `__TEXT,__eh_frame` CIE/FDE grammar and qualify additional C++, Objective-C, and Rust
  language forms, including archive debug-map inputs.
- [x] Broaden ARM64 subtractor relocation coverage beyond the validated ordinary 64-bit static-data
  form.
- [x] Expand dylib, proc-macro, Rust TLS, crate-type, and stress qualification.
- [x] Expand the Apple differential corpus and retain reproducible ARM64 Rust workload evidence.

x86_64 macOS is out of scope.
