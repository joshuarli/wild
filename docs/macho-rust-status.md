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
| ABI-level symbols | Bounded ARM64 fixtures cover tentative/common `N_UNDF` definitions (size and `n_desc` alignment in `__DATA,__common`), direct `N_INDR` aliases, `N_PEXT` visibility, hidden synthetic `___dso_handle`, C++ initialization/`atexit`/destruction, and Rust calling a native C function. Weak dylib imports retain `N_WEAK_REF` separately from weak definitions: all-weak dependencies use `LC_LOAD_WEAK_DYLIB` and the chained-import weak bit, while an unprovided weak import remains an undefined-symbol error. Absolute symbols, alias chains, and broad mixed-language qualification remain outside this bounded result. | partial; focused Apple controls and Wild runtime/structural fixtures green |
| ARM64 relocations / thunks | Validates supported standalone forms, `POINTER_TO_GOT`, local and dylib-imported TLVP descriptors, paired `ADDEND`, bounded ordinary-data `SUBTRACTOR`/`UNSIGNED` expressions, and out-of-range `BRANCH26` via nearby text islands. Authenticated paths remain explicitly diagnosed or absent. | partial; unqualified |
| Chained fixups | Plans address-ordered imported binds and local rebases per segment; gaps, leading local slots, 16 KiB pages, and malformed encodings are handled. Wider pointer-format/arm64e qualification remains. | partial; unqualified |
| Dylib output / rpaths / exports | Emits `MH_DYLIB`, `LC_ID_DYLIB`, requested `LC_RPATH`, and omits executable-only commands; C runtime smoke passes. Dependency ordinals, weak/reexport behavior, and Rust dylib qualification remain. | partial; unqualified |
| Dead strip / atoms | `MH_SUBSECTIONS_VIA_SYMBOLS` inputs are split into live symbol-delimited spans under `-dead_strip`; whole-section behavior is retained otherwise. | partial; differential smoke green |
| TLS, compact unwind, DWARF, string merging | A local C TLS descriptor fixture executes successfully. ARM64 compact frame/frameless rows, personality pointers, and LSDAs are synthesized and a C++ throw/catch fixture passes. Bounded ARM64 DWARF-mode rows now serialize their live `__eh_frame` CIE/FDE records and pass a Rust `panic=unwind` / `catch_unwind` smoke under `-dead_strip`. Ordinary C debug data is represented only by a bounded `dsymutil` debug map; final executables intentionally do not copy `__DWARF`. | partial; bounded unwind and C debug-map smoke green |

## Compatibility matrix

| Facility | Minimal fixture | Apple differential | Rust integration | Stress test | Status |
| --- | --- | --- | --- | --- | --- |
| ARM64 executable | existing `wild/tests/sources/macho/trivial` | pending | fresh stable Cargo bin and default `cargo test` link and run | n/a | smoke green |
| SDK `.tbd` / libSystem | existing `trivial-libsystem` | pending | pending | n/a | baseline only |
| dylib | `trivial-dynamic` now links its `foo.c` dylib with Wild and consumes it at runtime | pass | C runtime pass | n/a | smoke green |
| framework | none | pending | pending | n/a | unqualified |
| dead strip | `macho/dead-strip` | code/data/export parity pass | C runtime pass | pending | atom smoke green |
| ABI-level symbols | `macho/common-symbols`, `symbol-aliases`, `weak-symbols`, `weak-undefined`, `cxx-init-teardown` | Apple controls establish common/alias/weak behavior | `macho/rust-native-ffi` calls C through Wild | pending | bounded C/C++/Rust smoke green |
| TLS | `macho/tls-local`, `macho/tls-dynamic`, `macho/rust-thread-local` | Apple ld binds the imported descriptor through `__got`; ld64.lld uses `__thread_ptrs` | C and Rust two-thread runtime passes under Wild; Rust static/dylib TLS qualification remains external | pending | bounded C/Rust local/dylib smoke green |
| compact unwind | `macho/exception` C++ throw/catch; `macho/rust-panic-unwind` | structural section/header check; C++ and Rust runtime pass | ARM64 Rust `panic=unwind` / `catch_unwind` under `-dead_strip` | pending | bounded ARM64 support |
| DWARF / dSYM / LLDB | `macho/debug-dwarf` C `-g -dead_strip` | Apple ld and ld64.lld establish the `N_SO`/`N_OSO`/paired-`N_FUN` control shape; Wild `dsymutil --dump-debug-map` passes | generated dSYM verifies; LLDB source breakpoint/backtrace and C parameter inspection pass | pending | bounded loose-object ARM64 C support |
| chained fixups | existing output inspection only | pending | pending | pending | unqualified |
| branch islands | `macho/branch-island`, `macho/branch-islands` | Apple links forced overflows | C runtime pass | multiple islands pass | ARM64 smoke green |

## Expanded ARM64 qualification observations

These controlled runs distinguish a working smoke from a production gate. Apple-linked controls
passed wherever Wild is listed as failing.

| Workflow | Current Wild result | Next required work |
| --- | --- | --- |
| Rust/C `Security` framework | links and runs | retain as a permanent integration fixture |
| C local and dylib TLS | `macho/tls-dynamic` passes an imported descriptor two-thread independence smoke under `-dead_strip` and PIE/ASLR | broaden TLS/dylib coverage |
| Rust `cdylib` consumed from C | retained Cargo workspace links and runs through Wild; the existing integration harness cannot replay rustc's generated export-list file | fix save-dir retention of `-exported_symbols_list`, then add a permanent C consumer |
| Rust `dylib` consumed from Rust | retained Cargo workspace links and runs through Wild | add Cargo crate-graph coverage outside the one-source integration harness |
| Proc macro crate | retained Cargo workspace compiles, loads, and runs through Wild | add Cargo crate-graph coverage outside the one-source integration harness |
| Rust `thread_local!` / `cargo test` | permanent `macho/rust-thread-local` two-thread fixture and default `cargo test` pass through Wild | exercise static/dylib TLS matrix |
| C++ throw/catch | links, emits `__TEXT,__unwind_info`, and catches at runtime | broaden compact-unwind differential coverage |
| Rust `panic=unwind` | `macho/rust-panic-unwind` selects live CIE/FDE records, rewrites DWARF compact-unwind FDE offsets, and catches a panic at runtime under `-dead_strip` | broaden CIE/FDE grammar and crate/stress coverage |
| C DWARF / `dsymutil` | `macho/debug-dwarf` emits `N_SO`, `N_OSO`, and live-atom `N_FUN` pairs; `dsymutil` makes a verified dSYM and LLDB stops at the C source line under `-dead_strip` | qualify more C shapes and debug-map inputs |
| `-dead_strip` and `-force_load` | dead C code/data and unreferenced forced archive member are covered | add stress/edge corpus |
| 138 MiB fragmented branch | Apple and Wild both link/run through nearby islands | larger stress qualification |
| 700 imported function binds | links/runs across multiple pages | extend fixups from imported GOT binds to local rebases |

## Reproducers and qualification commands

* Fast existing Mach-O suite: `cargo test --profile ci --workspace --features macho`.
* Existing CI build: `cargo build --profile ci --workspace --no-default-features`.
* Focused permanent Rust TLS fixture: `WILD_TEST_IGNORE_FORMAT=1 cargo test -p wild-linker
  --features macho --test integration_tests -- 'macho/aarch64/rust-thread-local/default'`.
* Focused C debug-map fixture: `WILD_TEST_IGNORE_FORMAT=1 cargo test --profile ci -p wild-linker
  --test integration_tests --features macho -- 'macho/aarch64/debug-dwarf/default'`. Its output
  can be checked with `dsymutil --dump-debug-map <binary>`, `dsymutil <binary>`, and
  `dwarfdump --verify <binary>.dSYM/Contents/Resources/DWARF/<binary-name>`.
* Focused ARM64 subtractor fixture: `WILD_TEST_IGNORE_FORMAT=1 cargo test --profile ci -p
  wild-linker --features macho --test integration_tests -- 'macho/aarch64/subtractor-reloc/default'`.
  Apple clang emits an adjacent, same-offset `ARM64_RELOC_SUBTRACTOR` then
  `ARM64_RELOC_UNSIGNED` pair, both external-symbol, non-PC-relative, 64-bit records. The
  unsigned half names the minuend, the subtractor names the subtrahend, and the in-place word is
  the two's-complement addend. Wild preserves that expression through graph loading and writing:
  same-object local `ltmp` targets, a target defined by another object, an absolute minuend,
  `-dead_strip` atom retention, and an in-image-looking arithmetic result that must not become a
  dyld rebase all execute against Apple controls. This bounded support rejects malformed
  ordering/fields and dylib or weak-import operands; `__eh_frame` keeps its separately validated
  reconstruction path.
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
or debug information and the other qualification gates listed below. The invocation selects Wild;
it does not fall back to Apple ld.

### Existing integration-harness coverage and Cargo boundary

`wild/tests/integration_tests.rs` can compile a standalone `.rs` primary source, and its `Shared`
input can invoke rustc with `--crate-type cdylib`. The permanent `macho/rust-thread-local` fixture
uses the first path and verifies independent Rust TLS values in the parent and child threads.

The `Shared` cdylib path is not yet a passing fixture: rustc's save-dir replay contains an
`-exported_symbols_list` file under a generated `rustcwsAsIT` path, but Wild does not copy that
file into the save directory. The exact current failure is:

```text
ld: -exported_symbols_list file '.../rustcwsAsIT/list' could not be opened, errno=2
```

The smallest implementation prerequisite for a permanent Rust cdylib/C consumer fixture is to
retain that option's file in the save-dir input set; do not add a permanently failing fixture.

Cargo Rust `dylib` consumption and proc-macro loading require multiple packages and distinct
rustc invocations (producer, consumer, and proc-macro host). They therefore do not fit the
single-source compiler model in this integration harness. Requalify them in a retained temporary
Cargo workspace with the following repeatable controls:

```sh
cargo build -p wild-linker --features macho --bin wild
WILD="$PWD/target/debug/wild"
CARGO_TARGET_DIR="$QUAL_DIR/target" \
RUSTFLAGS="-Clinker=clang -Clink-arg=--ld-path=$WILD" \
  cargo run --manifest-path "$QUAL_DIR/Cargo.toml" \
    --target aarch64-apple-darwin -vv
```

The workspace should contain a path-dependent Rust `dylib` producer/consumer pair and a
`proc-macro = true` crate plus a consumer. Preserve each `cargo -vv` log, the `WILD_SAVE_DIR`
`run-with` file, and the exit status; accept a result only when the final rustc/clang invocation
contains `--ld-path=$WILD` and the resulting ARM64 consumer runs. This is the reproducible Cargo
qualification plan for those crate graphs without adding a parallel test framework here.

### Bounded C `dsymutil` debug map

`macho/debug-dwarf` is the permanent ARM64 C control: clang compiles one loose `-g` object and
the link uses `-dead_strip`. Wild intentionally leaves final `__DWARF` sections out of the
executable, as Apple ld and ld64.lld do. Instead `MachO::allocate_object_symtab_space` reserves,
and `write_dsymutil_debug_map` emits, `N_SO`, `N_OSO`, one start/terminator `N_FUN` pair for each
live executable atom, and the terminating empty `N_SO`. Start addresses use the post-GC compacted
section mapping; terminators retain each atom's original input length. `dsymutil` owns DWARF
relocation and address rewriting when it builds the dSYM.

The supported input is deliberately small: a loose ARM64 Mach-O object with
`MH_SUBSECTIONS_VIA_SYMBOLS`, ordinary C (`DW_LANG_C89`, `C`, `C99`, `C11`, or `C17`) debug data,
and live, non-merged executable atoms. The fixture checks that a dead static function is absent
from the map, runs `dsymutil --dump-debug-map`, verifies the generated dSYM with `dwarfdump`, and
uses an LLDB batch source breakpoint/backtrace to inspect `value = 41`. C++, Objective-C,
archives, split DWARF, and all Rust debug-info modes are not claimed by this implementation.
There is no final-section copy, generic debug relocation writer, or Rust dSYM claim hidden behind
this C smoke.

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
  dylib-imported TLVP descriptor pointers, and paired `ADDEND` forms. A dynamic TLVP is recorded
  as the generic TLS-descriptor resource, allocated in Mach-O's dedicated
  `__DATA,__thread_ptrs` (`S_THREAD_LOCAL_VARIABLE_POINTERS`) section rather than as an ordinary
  GOT entry, and emitted as a normal chained bind at that slot. The writer preserves the imported
  ADRP/LDR pair; it performs the local-descriptor LDR-to-ADD rewrite only for in-image TLS.
  `macho/tls-local` proves a C local TLS variable links and has per-process runtime initialization
  through the native dyld bootstrap path; `macho/tls-dynamic` proves imported TLS shares the
  producer's value within each thread, remains isolated between two threads, and survives
  `-dead_strip` under PIE/ASLR. `macho/reloc-addend` proves a positive paired page addend at
  runtime.
* Mach-O allocation now reserves every GOT/PLT entry that resolution creation will consume. The
  minimal stable Cargo smoke therefore advances past its empty-`__got` layout invariant.
* Mach-O dynamic-library inputs are deduplicated by install name, rather than their distinct SDK
  stub paths, and all aliases use the retained load-command ordinal. `macho/dylib-dedup` proves
  Rust's `-lSystem -lc -lm` no longer makes dyld reject duplicate `libSystem` commands.
* Chained-fixup generation now uses actual dynamic GOT addresses, handles local gaps and multiple
  16 KiB pages, and validates its chain encoding. The minimal stable Cargo binary links and runs
  with Wild after its first dynamic bind at `__got + 0x68`.
* ARM64 DWARF compact-unwind rows now retain only live `__eh_frame` FDEs, serialize their final
  CIE/FDE records, and rewrite the compact-unwind low 24-bit FDE offsets. The serializer supports
  the Rust-produced DWARF32 `zR` / `zPLR` CIE grammar with an indirect PC-relative personality
  pointer; for a local personality it adds the required validated chained GOT rebase. Permanent
  `macho/rust-panic-unwind` runs Rust `panic=unwind` / `catch_unwind` with `-dead_strip`.

## Deferred / deliberately unsupported today

* Apple platforms other than macOS.
* Universal/fat output (thin binaries combined externally are sufficient).
* Incremental linking.
* x86_64 Mach-O is outside the agreed scope for this effort.
* C++/Objective-C/Rust/archived/split-DWARF dSYM debug maps and generic output-DWARF relocation.

## Next work items

1. Broaden final `__TEXT,__eh_frame` CIE/FDE grammar and qualify C++/Objective-C/Rust/archive
   debug-map inputs before designing any generic ordinary-DWARF relocation path.
2. Broaden subtractor coverage beyond the validated ordinary 64-bit static data form, and complete
   full dylib/proc-macro and Rust TLS qualification.
3. Expand the Apple-differential corpus and ARM64 Rust crate-type/stress qualification.
