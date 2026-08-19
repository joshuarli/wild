# macOS Rust compatibility status

This ledger records the evidence behind the Mach-O port. It deliberately distinguishes
implemented behavior from planned behavior: an unchecked item is not a claim of support.

## Baseline

| Item | Value |
| --- | --- |
| Source commit | `563ec0ba7336a7700c00423435f4297b44231274` (`plan`; one commit ahead of upstream `82abac93d8436601c27fae33295b84a67bc70e8b`) |
| Host | Apple Silicon macOS 26.5.2 (25F84) |
| Xcode / SDK | Xcode 26.6 (17F113), macOS SDK 26.5 |
| SDK path | `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk` |
| Rust stable | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |
| Rust nightly available | `nightly-aarch64-apple-darwin` (also dated 2026-04-20, 2026-07-20, and 2026-07-24) |
| Primary qualification target | `aarch64-apple-darwin` |
| Scope boundary | `x86_64-apple-darwin` is explicitly out of scope; this ledger qualifies ARM64 only |
| Apple toolchain | Apple clang 21.0.0; ld64 1267; Homebrew `ld64.lld` present |

## Current phase

Phase 1–10: baseline, architecture audit, recorder infrastructure, and the first bounded
Mach-O semantic implementations. The repository's existing macOS CI job builds the workspace
and runs `cargo test --profile ci --workspace --features macho`; it is the existing fast Mach-O
regression entry point. This remains a regression gate, not production qualification.

Baseline checks completed on this host:

* `cargo build --profile ci --workspace --no-default-features` — pass.
* `WILD_TEST_IGNORE_FORMAT=1 cargo test --profile ci --workspace --features macho` — pass
  (185 `libwild` tests, 35 Mach-O integration tests, recorder tests, and remaining workspace/doc
  tests).
* Without `WILD_TEST_IGNORE_FORMAT=1`, only tidy tests fail because this host lacks `taplo` and
  `clang-format`; this is the same exemption configured for the macOS CI job. No formatter or
  linter was run as part of this work.
* The existing Wild output for `trivial.c` is a valid signed ARM64 `MH_EXECUTE`; `codesign -dv`
  confirms its embedded ad-hoc signature. This is an executable smoke result, not a production
  qualification result.

## Evidence and current limits

The current backend is explicitly incomplete. The following are implementation targets rather
than supported facilities:

| Facility | Evidence | Status |
| --- | --- | --- |
| Mach-O argument semantics | Models ARM64, dylib/executable, install names, rpaths, export lists, framework paths, strip options, and input-local `-force_load`. | partial |
| Section/symbol classification | Handles data access, debug/non-alloc, `__DATA_CONST`, TLV storage, no-dead-strip, C strings, and Mach-O-specific no-op hooks. | partial |
| ARM64 relocations / thunks | Validates supported standalone forms, `POINTER_TO_GOT`, local executable TLVP descriptors, paired `ADDEND`, and out-of-range `BRANCH26` via nearby text islands. `SUBTRACTOR`, dynamic-TLVP, and authenticated paths remain explicitly diagnosed or absent. | partial; unqualified |
| Chained fixups | Plans address-ordered imported binds and local rebases per segment; gaps, leading local slots, 16 KiB pages, and malformed encodings are handled. Wider pointer-format/arm64e qualification remains. | partial; unqualified |
| Dylib output / rpaths / exports | Emits `MH_DYLIB`, `LC_ID_DYLIB`, requested `LC_RPATH`, and omits executable-only commands; C runtime smoke passes. Dependency ordinals, weak/reexport behavior, and Rust dylib qualification remain. | partial; unqualified |
| Dead strip / atoms | `MH_SUBSECTIONS_VIA_SYMBOLS` inputs are split into live symbol-delimited spans under `-dead_strip`; whole-section behavior is retained otherwise. | partial; differential smoke green |
| TLS, compact unwind, DWARF, string merging | A local C TLS descriptor fixture executes successfully. ARM64 compact frame/frameless rows, personality pointers, and LSDAs are synthesized and a C++ throw/catch fixture passes. ARM64 DWARF-mode unwind rows are rejected because final `__eh_frame` serialization is not implemented. | partial; unqualified |

## Compatibility matrix

| Facility | Minimal fixture | Apple differential | Rust integration | Stress test | Status |
| --- | --- | --- | --- | --- | --- |
| ARM64 executable | existing `wild/tests/sources/macho/trivial` | pending | fresh stable Cargo bin and default `cargo test` link and run | n/a | smoke green |
| SDK `.tbd` / libSystem | existing `trivial-libsystem` | pending | pending | n/a | baseline only |
| dylib | `trivial-dynamic` now links its `foo.c` dylib with Wild and consumes it at runtime | pass | C runtime pass | n/a | smoke green |
| framework | none | pending | pending | n/a | unqualified |
| dead strip | `macho/dead-strip` | code/data/export parity pass | C runtime pass | pending | atom smoke green |
| TLS | `macho/tls-local` | structural comparison pending | C runtime pass; Rust static/dylib TLS re-qualification pending | pending | local executable smoke green |
| compact unwind | `macho/exception` C++ throw/catch | structural section/header check; runtime pass | Rust `panic=unwind` needs final `__eh_frame` | pending | bounded C++ support; Rust blocked |
| DWARF / dSYM / LLDB | none | pending | pending | pending | unqualified |
| chained fixups | existing output inspection only | pending | pending | pending | unqualified |
| branch islands | `macho/branch-island`, `macho/branch-islands` | Apple links forced overflows | C runtime pass | multiple islands pass | ARM64 smoke green |

## Expanded ARM64 qualification observations

These controlled runs distinguish a working smoke from a production gate. Apple-linked controls
passed wherever Wild is listed as failing.

| Workflow | Current Wild result | Next required work |
| --- | --- | --- |
| Rust/C `Security` framework | links and runs | retain as a permanent integration fixture |
| C local and dylib TLS | links and passes a two-thread independence smoke | broaden TLS/dylib coverage |
| Rust `cdylib` consumed from C | links and runs | export, unwind, and debug qualification |
| Rust `dylib` consumed from Rust | consumer segfaulted before general local rebases | re-qualify after rebase work |
| Proc macro crate | rustc segfaulted before general local rebases | re-qualify after rebase work |
| Rust `thread_local!` / `cargo test` | default `cargo test` now passes through Wild; `thread_local!` needs re-qualification | exercise static/dylib TLS matrix |
| C++ throw/catch | links, emits `__TEXT,__unwind_info`, and catches at runtime | broaden compact-unwind differential coverage |
| Rust `panic=unwind` | intentionally rejected when a live row uses ARM64 DWARF mode (`0x03000000`) | select, relocate, and serialize final `__TEXT,__eh_frame` CIE/FDE records |
| DWARF / `dsymutil` | debug sections are dropped; `dsymutil` reports no debug symbols | retain and relocate debug sections |
| `-dead_strip` and `-force_load` | dead C code/data and unreferenced forced archive member are covered | add stress/edge corpus |
| 138 MiB fragmented branch | Apple and Wild both link/run through nearby islands | larger stress qualification |
| 700 imported function binds | links/runs across multiple pages | extend fixups from imported GOT binds to local rebases |

## Reproducers and qualification commands

* Fast existing Mach-O suite: `cargo test --profile ci --workspace --features macho`.
* Existing CI build: `cargo build --profile ci --workspace --no-default-features`.
* Rust-to-Darwin command capture: [`darwin-linker-recorder.md`](darwin-linker-recorder.md)
  documents the new `darwin-linker-recorder` wrapper and its exact NUL-delimited replay records.
* A fresh stable `aarch64-apple-darwin` Cargo binary was captured through that recorder. Its final
  Clang-driver invocation contained object files, Rust archives, `-lSystem -lc -lm`, `-arch arm64`,
  `-mmacosx-version-min=11.0.0`, `-Wl,-dead_strip`, `-o`, and `-nodefaultlibs`; Apple clang
  completed the delegated link successfully. The capture is deliberately ephemeral because its
  absolute paths contain Cargo hash and temporary-directory components; `argv.nul` is the durable
  recording format for future corpus fixtures.
* Every future Rust/Cargo qualification must record the exact linker argv, working directory,
  SDK path, toolchain version, and proof that Wild performed the final link. No Apple-linker
  fallback is accepted as a passing Wild qualification.

### Current Rust smoke: local executable links and runs

The following current-stable Cargo binary now links through Wild and executes successfully. The
Rust link includes local TLVP descriptors, paired addends from `libstd`, SDK stub aliases for
`libSystem`, and a `__got` whose first dynamic bind follows `0x68` bytes of local slots. The
chained-fixup plan records the first page start as `0x68`, so dyld begins the chain at the first
actual bind rather than decoding a local slot as a pointer.

```sh
cargo build -p wild-linker --features macho --bin wild
scratch="$(mktemp -d)"
cargo init --bin --name wild_macho_smoke "$scratch"
RUSTFLAGS="-C linker=clang -C link-arg=--ld-path=$PWD/target/debug/wild" \
  cargo run --manifest-path "$scratch/Cargo.toml"
```

This is a smoke result only. It is not evidence for dynamic TLS, proc macros, Rust panic/unwind,
or debug information and the other qualification gates
listed below. The invocation selects Wild; it does not fall back to Apple ld.

### Local chained-rebase regression

The previous Rust test-harness null callback is fixed by per-segment address-ordered chained
rebases. Permanent `macho/local-rebase` and `macho/local-got-rebase` fixtures cover ordinary
local data pointers and local GOT entries under PIE/ASLR; a fresh default Cargo test also passes
through Wild. This is still a smoke result, not qualification of every pointer format or arm64e.

## Upstream audit

The configured remote is a user fork, but upstream `wild-linker/wild` resolves to
`82abac93d8436601c27fae33295b84a67bc70e8b`, the parent of this worktree's `plan` commit.
Upstream still tracks unresolved fundamental Mach-O work including dylib output (#2161), TLS
(#2071), compact unwind (#2066), DWARF (#2068), and multi-page chained fixups (#2076). Recent
upstream Mach-O work covers dynamic exports, arbitrary segments, same-path replacement, and ADRP
relaxation APIs; none removes the known correctness gaps listed above.

## Changes and regressions added in this phase

* `darwin-linker-recorder` writes exact Cargo/rustc Darwin-linker captures, documented in
  [`darwin-linker-recorder.md`](darwin-linker-recorder.md).
* Darwin argument parsing now models framework lookup (`-F` / `-framework`), dylib output,
  `-install_name`, `-rpath`, `-exported_symbols_list`, strip modes, and explicit ARM64 target
  validation. Unsupported `-x` is diagnosed rather than ignored.
* Wild emits `MH_DYLIB` / `LC_ID_DYLIB` for dylibs, `LC_RPATH` as requested, and keeps executable
  commands out of dylibs. The existing `trivial-dynamic` fixture now builds the dependency dylib
  with Wild rather than forcing lld, then executes the consumer successfully.
* Mach-O `__cstring` now reuses the generic merge map correctly: symbol values use a
  section-relative input offset, merged bytes are emitted before code-signature hashing, and
  Mach-O symtab entries retain the correct output section. This fixed an integration regression
  exposed by enabling C-string merging.
* AArch64 relocation validation now rejects malformed standalone encodings deterministically,
  supports both `ARM64_RELOC_POINTER_TO_GOT` representations, local executable TLVP descriptors,
  and paired `ADDEND` forms. It reports subtractor, dynamic-TLVP, and arm64e forms explicitly
  instead of treating them as unknown or silently applying an invalid result. `macho/tls-local`
  proves a C local TLS variable links and has per-process runtime initialization through the native
  dyld bootstrap path; `macho/reloc-addend` proves a positive paired page addend at runtime.
* Mach-O allocation now reserves every GOT/PLT entry that resolution creation will consume. The
  minimal stable Cargo smoke therefore advances past its empty-`__got` layout invariant.
* Mach-O dynamic-library inputs are deduplicated by install name, rather than their distinct SDK
  stub paths, and all aliases use the retained load-command ordinal. `macho/dylib-dedup` proves
  Rust's `-lSystem -lc -lm` no longer makes dyld reject duplicate `libSystem` commands.
* Chained-fixup generation now uses actual dynamic GOT addresses, handles local gaps and multiple
  16 KiB pages, and validates its chain encoding. The minimal stable Cargo binary links and runs
  with Wild after its first dynamic bind at `__got + 0x68`.

## Deferred / deliberately unsupported today

* Apple platforms other than macOS.
* Universal/fat output (thin binaries combined externally are sufficient).
* Incremental linking.
* x86_64 Mach-O is outside the agreed scope for this effort.

## Next work items

1. Serialize final `__TEXT,__eh_frame` and retain/relocate ordinary DWARF for Rust panic and
   debugger workflows.
2. Complete dynamic TLS, subtractor relocations, and full dylib/proc-macro qualification.
3. Expand the Apple-differential corpus and ARM64 Rust crate-type/stress qualification.
