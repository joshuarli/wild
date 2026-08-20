# macOS Rust compatibility status

This ledger records the evidence behind the Mach-O port. It deliberately distinguishes
implemented behavior from planned behavior: an unchecked item is not a claim of support.

## Baseline

| Item | Value |
| --- | --- |
| Source baseline | Current checked-out tree; every command below names its exact toolchain and is reproduced from the committed CI configuration |
| Host | Apple Silicon macOS 26.5.2 (25F84) |
| Xcode / SDK | Xcode 26.6 (17F113), macOS SDK 26.5 |
| SDK path | `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk` |
| Rust stable | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |
| Rust nightly qualification target | `nightly-2026-07-24`: `rustc 1.99.0-nightly (89c61a754 2026-07-23)` and Cargo `1.99.0-nightly (3efb1f477 2026-07-17)` |
| Requested nightly components | `rust-src`, `llvm-tools-aarch64-apple-darwin` installed |
| Primary qualification target | `aarch64-apple-darwin` |
| Scope boundary | `x86_64-apple-darwin` is explicitly out of scope; this ledger qualifies ARM64 only |
| Apple toolchain | Apple clang 21.0.0; ld64 1267; Homebrew `ld64.lld` present |

## Current phase

Phase 1–10: architecture implementation plus expanding ARM64 qualification. The repository's
ARM64 macOS CI job installs `nightly-2026-07-24` with `rust-src` and `llvm-tools`, then explicitly
runs `cargo +nightly-2026-07-24 build/test --profile ci --workspace --features macho`. Stable
coverage remains in the Linux jobs. This is a fast regression entry point, not a declaration of
production completion.

Baseline checks completed on this host:

* `cargo build --profile ci --workspace --no-default-features` — pass.
* `WILD_TEST_IGNORE_FORMAT=1 cargo test --profile ci --workspace --features macho` — pass
  (185 `libwild` tests, 35 Mach-O integration tests, recorder tests, and remaining workspace/doc
  tests).
* `WILD_TEST_IGNORE_FORMAT=1 cargo +nightly-2026-07-24 test --profile ci --workspace --features
  macho` — pass (all workspace unit tests and doctests, including 208 `libwild` tests and 67
  ARM64 Mach-O integrations). This is the reproducible dated-nightly gate; it is run with the
  installed `rust-src` and `llvm-tools` components, not by falling back to stable Rust.
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
| Section/symbol classification | Carries section-derived function/TLS facts beside raw nlists, handles data access, debug/non-alloc, `__DATA_CONST`, TLV storage, no-dead-strip, C strings, and Mach-O-specific no-op hooks. `__thread_bss` extends its containing `__DATA` segment, unlike ELF's `PT_TLS`-only zero-fill convention. | partial |
| ABI-level symbols | Bounded ARM64 fixtures cover tentative/common `N_UNDF` definitions (size and `n_desc` alignment in `__DATA,__common`), direct `N_INDR` aliases, `N_PEXT` visibility, hidden synthetic `___dso_handle`, C++ initialization/`atexit`/destruction, and Rust calling a native C function. Weak dylib imports retain `N_WEAK_REF` separately from weak definitions: all-weak dependencies use `LC_LOAD_WEAK_DYLIB` and the chained-import weak bit, while an unprovided weak import remains an undefined-symbol error. Absolute symbols, alias chains, and broad mixed-language qualification remain outside this bounded result. | partial; focused Apple controls and Wild runtime/structural fixtures green |
| ARM64 relocations / thunks | Validates supported standalone forms, `POINTER_TO_GOT`, local and dylib-imported TLVP descriptors, paired `ADDEND`, bounded ordinary-data `SUBTRACTOR`/`UNSIGNED` expressions, and out-of-range `BRANCH26` via nearby text islands. Authenticated paths remain explicitly diagnosed or absent. | partial; unqualified |
| Chained fixups | Plans address-ordered imported binds and local rebases per segment; gaps, leading local slots, 16 KiB pages, and malformed encodings are handled. `macho/chained-fixups-multipage` executes 2300 imported `__got` binds across two pages, while `macho/chained-fixups-tlvp` executes two imported descriptor binds in `__thread_ptrs`. Wider pointer-format/arm64e qualification remains. | partial; bounded ARM64 runtime green |
| Dylib output / rpaths / exports | Emits `MH_DYLIB`, `LC_ID_DYLIB`, requested `LC_RPATH`, and omits executable-only commands. Undefined nlists owned by input dylibs remain dyld imports rather than being recursively rejected by the static link. C and bounded Rust `dylib` producer/consumer runtime controls pass. Dependency ordinals and weak/reexport behavior remain. | partial; bounded C/Rust dylib runtime green |
| Dead strip / atoms | `MH_SUBSECTIONS_VIA_SYMBOLS` inputs are split into live symbol-delimited spans under `-dead_strip`; whole-section behavior is retained otherwise. | partial; differential smoke green |
| TLS, compact unwind, DWARF, string merging | A local C TLS descriptor fixture executes successfully. ARM64 compact frame/frameless rows, personality pointers, and LSDAs are synthesized and a C++ throw/catch fixture passes. Bounded ARM64 DWARF-mode rows now serialize their live `__eh_frame` CIE/FDE records and pass a Rust `panic=unwind` / `catch_unwind` smoke under `-dead_strip`. Ordinary C debug data is represented only by a bounded `dsymutil` debug map; final executables intentionally do not copy `__DWARF`. | partial; bounded unwind and C debug-map smoke green |

## Compatibility matrix

| Facility | Minimal fixture | Apple differential | Rust integration | Stress test | Status |
| --- | --- | --- | --- | --- | --- |
| ARM64 executable | existing `wild/tests/sources/macho/trivial` | pending | fresh stable Cargo bin and default `cargo test` link and run | n/a | smoke green |
| SDK `.tbd` / libSystem | `macho/sdk-libcompression` links a versionless SDK TBD and runs; `macho/sdk-accelerate-nested-reexport` resolves an in-file Accelerate → vecLib → BLAS export; `macho/sdk-libiconv-external-reexport` resolves libiconv's separate libcharset child while retaining only libiconv in the consumer | Apple controls and Wild runtime/load-command assertions pass | pending | n/a | bounded ARM64 SDK-stub support |
| dylib | `trivial-dynamic` now links its `foo.c` dylib with Wild and consumes it at runtime; `macho/dylib-install-name-consumer` consumes an Apple-built physical-name mismatch through its `LC_ID_DYLIB` | Apple control, Wild load-command assertion, and C runtime pass | retained Cargo Rust `dylib` producer/consumer links each final artifact through Wild and loads through `@loader_path` rpath | n/a | bounded C/Rust dylib runtime green |
| proc macro | `cargo_macho_macro_producer` expands through `TokenStream::from_str` into `40 + 2` | Apple control builds the producer/consumer pair | retained Cargo producer and consumer final links select Wild; the consumer runs the non-identity expansion | n/a | bounded ARM64 Cargo proc-macro runtime green |
| framework | `macho/framework-security` calls `SecRandomCopyBytes` through `-framework Security` | Apple control and Wild output both carry the current SDK Security framework load command; both run successfully | C framework consumer runs through Wild | n/a | bounded ARM64 framework runtime/structural green |
| Objective-C selector dispatch | `macho/objc-runtime`, `objc-multi-selector`, and `objc-dead-selector` compile normal ARC calls without compiler workarounds | Apple ld establishes one 32-byte `__objc_stubs` veneer and one chained-rebase `__objc_selrefs` slot per live selector | n/a | repeated selectors deduplicate lexically; a dead selector atom emits neither synthetic section | bounded ARM64 Objective-C runtime green |
| dead strip | `macho/dead-strip` | code/data/export parity pass | C runtime pass | pending | atom smoke green |
| ABI-level symbols | `macho/common-symbols`, `symbol-aliases`, `weak-symbols`, `weak-undefined`, `cxx-init-teardown` | Apple controls establish common/alias/weak behavior | `macho/rust-native-ffi` calls C through Wild | pending | bounded C/C++/Rust smoke green |
| TLS | `macho/tls-local`, `macho/tls-dynamic`, `macho/rust-thread-local` | Apple ld binds the imported descriptor through `__got`; ld64.lld uses `__thread_ptrs` | C and Rust two-thread runtime passes under Wild; Rust static/dylib TLS qualification remains external | pending | bounded C/Rust local/dylib smoke green |
| compact unwind | `macho/exception` C++ throw/catch; `macho/rust-panic-unwind` | structural section/header check; C++ and Rust runtime pass | ARM64 Rust `panic=unwind` / `catch_unwind` under `-dead_strip` | pending | bounded ARM64 support |
| DWARF / dSYM / LLDB | `macho/debug-dwarf` C `-g -dead_strip` | Apple ld and ld64.lld establish the `N_SO`/`N_OSO`/paired-`N_FUN` control shape; Wild `dsymutil --dump-debug-map` passes | generated dSYM verifies; LLDB source breakpoint/backtrace and C parameter inspection pass | pending | bounded loose-object ARM64 C support |
| chained fixups | `macho/chained-fixups-tlvp`, `macho/chained-fixups-multipage` | Apple controls and Wild runtime pass | pending | 2300 imported `__got` binds cross two 16 KiB pages; two imported `__thread_ptrs` binds exercise a non-zero TLVP page offset | bounded ARM64 runtime green |
| branch islands | `macho/branch-island`, `macho/branch-islands` | Apple links forced overflows | C runtime pass | multiple islands pass | ARM64 smoke green |

## Expanded ARM64 qualification observations

### SDK TBD and dylib identity metadata

`macho_stub_library::parse_defined_library_with_external_reexports` accepts ARM64 TBD v4 roots that omit
`current-version`, as the current SDK `libcompression.tbd` does. Missing `current-version` and
`compatibility-version` each produce Apple's observed `1.0.0` consumer value. The parser walks
only ARM64e-compatible `reexported-libraries` reachable from the root, so an umbrella may reexport
another umbrella: the permanent Accelerate fixture imports `cblas_sdot` through
Accelerate → vecLib → libBLAS. If the child is in a separate SDK TBD, `input_data` locates its
physical `.tbd` from the active sysroot, root directory, or library search paths and retains that
mapped input for the link lifetime. `macho/sdk-libiconv-external-reexport` covers the current
libiconv → libcharset split. It retains the root current/compatibility pair and only the root
install name in the consumer load command, matching Apple's dyld-facing contract. Unsupported TBD
versions, duplicate install-name documents, and a reachable reexport whose external SDK child
cannot be located remain diagnosed.

`macho::DylibMetadata` carries one dynamic input's `LC_ID_DYLIB` install name plus its current and
compatibility versions from parsing through library deduplication, ordinal assignment, and
`macho_writer::write_dylib_command`. A consumer therefore names a Mach-O dylib by `LC_ID_DYLIB`,
not by its input filename. Apple control output for a physical `physical-name.dylib` with ID
`@rpath/contract-id.dylib`, current `7.8.9`, and compatibility `3.2.1` uses that ID and version
pair in its `LC_LOAD_DYLIB`; Wild now does likewise. Apple uses fixed timestamp `2` for an emitted
consumer load command, while a newly produced `LC_ID_DYLIB` uses timestamp `1` and the existing
`1.0.0` defaults. Weak dependencies still select `LC_LOAD_WEAK_DYLIB`; only their identity/version
payload is shared with ordinary dependencies.

The bounded permanent controls are `macho/sdk-libcompression`,
`macho/sdk-accelerate-nested-reexport`, `macho/sdk-libiconv-external-reexport`,
`macho/dylib-install-name-consumer`, and `macho/dylib-install-name-alias`. The libiconv control
checks that `/usr/lib/libiconv.2.dylib`, rather than its reexported
`/usr/lib/libcharset.1.dylib`, is present in the consumer. The custom consumer checks the exact
load-command path and `7.8.9` / `3.2.1` pair; the alias fixture proves the clang/ld64 spelling
`-dylib_install_name` produces a runnable dylib. This does not qualify platform variants beyond
macOS ARM64, non-v4 TBD formats, or broad framework/reexport semantics.

These controlled runs distinguish a working smoke from a production gate. Apple-linked controls
passed wherever Wild is listed as failing.

| Workflow | Current Wild result | Next required work |
| --- | --- | --- |
| C `Security` framework | permanent `macho/framework-security` fixture links with `-framework Security`, asserts the SDK install name/version, and runs the imported `SecRandomCopyBytes` call under Wild | broaden framework search-path and Rust framework coverage |
| C local and dylib TLS | `macho/tls-dynamic` passes an imported descriptor two-thread independence smoke under `-dead_strip` and PIE/ASLR | broaden TLS/dylib coverage |
| Rust `cdylib` consumed from C | permanent `macho/rust-cdylib-consumer` replays rustc's `cdylib` link through Wild, exports a C ABI function, and runs from a C consumer | broaden Rust dylib/export and mixed-language coverage |
| Rust `staticlib` consumed from C++ | ARM64-only `macho/aarch64/cargo-staticlib-native/default` builds with `nightly-2026-07-24`, checks C ABI exports, and links/runs native C++ consumers through Apple and explicitly through Wild; one control throws in C++, crosses Rust `extern "C-unwind"`, and catches in C++ | broaden the ABI and exception-stress matrix; x86_64 remains out of scope |
| Rust `dylib` consumed from Rust | `macho/aarch64/cargo-workspace-qualification/default` links the producer and consumer through Wild and runs the consumer via its Mach-O rpath | broaden dependency and TLS matrix |
| Proc macro crate | `macho/aarch64/cargo-workspace-qualification/default` links the proc-macro producer and consumer through Wild, loads the macro during compilation, and executes its non-identity expansion | broaden macro/crate stress coverage |
| Rust `thread_local!` / `cargo test` | permanent `macho/rust-thread-local` two-thread fixture and default `cargo test` pass through Wild | exercise static/dylib TLS matrix |
| C++ throw/catch | links, emits `__TEXT,__unwind_info`, and catches at runtime | broaden compact-unwind differential coverage |
| Rust `panic=unwind` | `macho/rust-panic-unwind` selects live CIE/FDE records, rewrites DWARF compact-unwind FDE offsets, and catches a panic at runtime under `-dead_strip` | broaden CIE/FDE grammar and crate/stress coverage |
| C DWARF / `dsymutil` | `macho/debug-dwarf` emits `N_SO`, `N_OSO`, and live-atom `N_FUN` pairs; `dsymutil` makes a verified dSYM and LLDB stops at the C source line under `-dead_strip` | qualify more C shapes and debug-map inputs |
| `-dead_strip` and `-force_load` | dead C code/data and unreferenced forced archive member are covered | add stress/edge corpus |
| 138 MiB fragmented branch | Apple and Wild both link/run through nearby islands | larger stress qualification |
| 2300 imported data binds | `macho/chained-fixups-multipage` runs after reading every `__got` slot across two 16 KiB pages | broaden segment/pointer-format and local-rebase coverage |
| Two imported TLS descriptors | `macho/chained-fixups-tlvp` runs through adjacent `__DATA,__thread_ptrs` chained binds; the second slot proves the LDR page offset is scaled | broaden TLS and multi-page descriptor coverage |

## Reproducers and qualification commands

* Fast existing Mach-O suite: `cargo test --profile ci --workspace --features macho`.
* Existing CI build: `cargo build --profile ci --workspace --no-default-features`.
* Focused permanent Rust TLS fixture: `WILD_TEST_IGNORE_FORMAT=1 cargo test -p wild-linker
  --features macho --test integration_tests -- 'macho/aarch64/rust-thread-local/default'`.
* Focused Apple-framework fixture: `WILD_TEST_IGNORE_FORMAT=1 cargo test --profile ci -p
  wild-linker --features macho --test integration_tests --
  'macho/aarch64/framework-security/default'`. It links the same ARM64 C consumer with Apple and
  Wild, checks `LC_LOAD_DYLIB` for the current SDK Security framework identity/version, and runs
  the imported call.
* Focused external-SDK-reexport fixture: `WILD_TEST_IGNORE_FORMAT=1 cargo test --profile ci -p
  wild-linker --features macho --test integration_tests --
  'macho/aarch64/sdk-libiconv-external-reexport/default'`. It resolves the separate
  `libcharset.1.tbd` child of the SDK's `libiconv.tbd`, then checks that only libiconv's install
  name is emitted into the ARM64 consumer.
* Cargo proc-macro and Rust-dylib qualification: `WILD_TEST_IGNORE_FORMAT=1 cargo test -p
  wild-linker --features macho --test integration_tests --
  'macho/aarch64/cargo-workspace-qualification/default'`. This retains the multi-package Cargo
  workspace and audits each final ARM64 Clang invocation printed by `cargo -vv` for Wild's
  `--ld-path`; it rejects any x86_64 final link.
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
`macho/rust-cdylib-consumer` uses the second path: its Rust producer's generated
`-exported_symbols_list` is copied into `WILD_SAVE_DIR` and rewritten in `run-with`, so the replay
links a cdylib through Wild and a C executable imports and calls `rust_cdylib_answer` at runtime.
The save-dir registration is ordinary path-valued option handling, not a cdylib special case; the
unit regression also covers the attached `-exported_symbols_list=path` spelling.

Cargo Rust `dylib` consumption and proc-macro loading require multiple packages and distinct
rustc invocations (producer, consumer, and proc-macro host). The existing integration runner
therefore registers a separate ARM64-only trial,
`macho/aarch64/cargo-workspace-qualification/default`, rather than pretending those graphs fit a
single-source fixture. Its retained workspace is `wild/tests/cargo_macho_qualification` and has a
path-dependent Rust `dylib` producer/consumer plus a `proc-macro = true` producer/consumer.

For every package the trial creates a fresh short `/tmp` Cargo target directory and invokes
`cargo +nightly-2026-07-24 build -vv` with `clang --ld-path=<Wild>`, `-v`, and
`-C prefer-dynamic`. The explicit selector is necessary because rustup chooses Cargo before it
opens a nested workspace's `rust-toolchain.toml`. The trial parses every final Clang link
transcript, requires that each expected producer and consumer artifact selected Wild, requires
`-arch arm64`, and rejects `x86_64`. The proc macro uses
`TokenStream::from_str("40 + 2")`, so the consumer proves that a loaded macro performed a
non-identity expansion. The Rust-dylib consumer is then executed after clearing the `DYLD_*`
library search overrides; `otool` additionally checks both its `@loader_path` rpath and its
`@rpath/libcargo_macho_dylib_producer.dylib` dependency. The trial then copies the retained
workspace into its temporary directory, changes only the copied dylib producer implementation
body while preserving its API and result, and rebuilds/runs the dylib consumer. Its second
transcript again requires both producer and consumer final ARM64 links through Wild; a snapshot
asserts that every retained fixture Rust source is unchanged. This coverage deliberately does not
use `WILD_SAVE_DIR` or the `cdylib` replay path above.

The separate ARM64-only `macho/aarch64/cargo-staticlib-native/default` trial builds
`wild/tests/cargo_macho_staticlib` with the fixture's exact `nightly-2026-07-24` toolchain and
uses that toolchain's `llvm-nm` for the archive export check. It then final-links native C++
consumers with `-arch arm64`: once with Apple ld as a control and once with explicit
`clang++ --ld-path=<Wild>`. The export consumer verifies two Rust `no_mangle` C functions and a
native callback. Its second consumer has C++ throw, Rust `unsafe extern "C-unwind"` bridge, and
C++ catch, proving the direct imported C++ typeinfo pointer is a chained bind rather than a
provisional local rebase. This bounded result excludes x86_64, non-macOS hosts, and broad C++ or
Rust ABI/exception qualification.

```sh
WILD_TEST_IGNORE_FORMAT=1 cargo +nightly-2026-07-24 test --profile ci -p wild-linker \
  --features macho --test integration_tests -- 'macho/aarch64/cargo-staticlib-native/default'
```

### Objective-C selector dispatch

Modern ARM64 Clang leaves an undefined `_objc_msgSend$selector` branch at an ordinary Objective-C
message send. That spelling is linker protocol, not a libobjc export. `MachO::raw_symbol_name`
resolves it through the real dynamic `_objc_msgSend` import while
`MachO::create_finalise_sizes_ext` retains each live selector branch and allocates one lexical
`__TEXT,__objc_stubs` entry plus one `__DATA,__objc_selrefs` slot per distinct selector.
`macho_writer::write_objc_message_stubs` emits ld64's fixed
`ADRP/LDR x1; ADRP/LDR x16; BR; BRK*3` veneer and adds the selector slot to the local chained
rebase plan. The selector is found through the final merged `__objc_methname` map, so identical
strings from different objects cannot retain stale input addresses.

`macho/objc-runtime` proves normal ARC dispatch through `NSObject` with the current SDK TAPI
`objc-classes` field materialized as class and metaclass symbols. `objc-multi-selector` proves
the 32-byte/8-byte-per-selector layout, lexical deduplication, and runtime dispatch; the minimal
assembler `objc-dead-selector` proves dead selector branches do not create output sections.
This is deliberately limited to Clang's `_objc_msgSend$<nonempty-selector>` ARM64 form. It does
not claim a generic Objective-C metadata linker, `-const_selrefs`, selector-stub branch islands,
or Objective-C dSYM support.

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
* SDK TBD reexports may be either additional YAML documents in the root stub or separately mapped
  child TBDs. `input_data::find_external_macho_stub_library` resolves the latter through the
  current ARM64 SDK search boundary, while `macho_stub_library` preserves the root metadata used by
  `macho_writer::write_dylib_command`; `macho/sdk-libiconv-external-reexport` verifies the
  libiconv → libcharset case without adding a libcharset load command to the consumer.
* Wild emits `MH_DYLIB` / `LC_ID_DYLIB` for dylibs, `LC_RPATH` as requested, and keeps executable
  commands out of dylibs. The existing `trivial-dynamic` fixture now builds the dependency dylib
  with Wild rather than forcing lld, then executes the consumer successfully. `MH_DYLIB` output
  starts at VM address zero and omits synthetic `__PAGEZERO`, matching dylib image-relative
  chained local rebases; `macho/dylib-local-rebase` calls through a local function pointer after
  dyld loads the dylib. The retained Cargo workspace additionally verifies a Rust `dylib`
  producer/consumer through its final `@loader_path` rpath.
* Mach-O nlists are now wrapped with immutable facts from their defining section. This preserves
  the fixed 16-byte output nlist ABI while allowing `File::is_func` and `File::is_tls` to classify
  data, code, and TLS precisely. A dylib's own unresolved nlists are left to dyld, matching an
  Apple `-undefined dynamic_lookup` control; regular-object undefined references remain normal
  link-time obligations. `macho/dylib-undefined` covers that boundary. Zero-fill TLS remains in
  the Mach-O `__DATA` segment and extends its VM size, which is required for Rust proc-macro
  dylibs to load.
* Mach-O `__cstring` uses the generic merge map with section-relative symbol offsets; merged bytes
  are emitted before code-signature hashing into the minimum-alignment part reserved by layout,
  without overwriting a preceding higher-alignment section with the same Mach-O identity.
  `macho/cstring-merging` proves equal literals from separate objects resolve to one address under
  `-dead_strip`. `macho/cstring-local-symbol-identity` additionally uses direct ARM64 `ADRP`/`ADD`
  references to different local literals at the same section-relative slot in two objects, with a
  preceding regular aligned `__cstring` part, and proves the prefix and both local targets retain
  their own bytes at runtime. This covers the cross-object/local-symbol case exposed by the
  retained Cargo `regex-min` corpus.
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
* A local definition may need both a chained-rebase GOT slot and a direct reference. Ordinary
  relocations now use that definition's symbol address instead of the resolution's GOT-adjusted
  raw value; `macho/local-got-rebase` calls the same local function both ways. This also covers
  Rust proc-macro bridge callbacks whose direct function pointer otherwise landed in
  non-executable `__DATA_CONST,__got`.
* The export trie similarly represents definitions, not relocation targets. A local function
  with a live GOT use exports `ResolutionExt::symbol_address` rather than its GOT-adjusted
  `raw_value`; dynamic and PLT targets retain their existing values. This prevents a `dlsym`
  client from executing a `__DATA_CONST,__got` slot. `macho/dylib-export-local-got` keeps both
  reference forms live and calls the exported definition at runtime.
* `S_MOD_INIT_FUNC_POINTERS` is a semantic liveness root under `-dead_strip`, not merely a
  section-name convention. Its entries are ordinary relocation edges, so this retains their
  target atoms while dead siblings stay eligible for stripping. `macho/cxx-init-dead-strip`
  loads a Wild-built C++ dylib and proves an initializer-only constructor runs while a hidden
  unused atom does not survive.
* Mach-O dynamic-library inputs are deduplicated by install name, rather than their distinct SDK
  stub paths, and all aliases use the retained load-command ordinal. `macho/dylib-dedup` proves
  Rust's `-lSystem -lc -lm` no longer makes dyld reject duplicate `libSystem` commands.
* Chained-fixup generation uses actual dynamic GOT addresses, handles local gaps and multiple
  16 KiB pages, and validates its chain encoding. `macho/chained-fixups-multipage` executes 2300
  distinct imported data binds across two `__DATA_CONST,__got` pages. A dynamic TLVP remains an
  LDR rather than the local-descriptor ADD rewrite, so its page offset must use the instruction's
  scaled low-12 encoding: `macho/chained-fixups-tlvp` executes two adjacent
  `__DATA,__thread_ptrs` binds and reaches the second slot at +8. The minimal stable Cargo binary
  also links and runs with Wild after its first dynamic bind at `__got + 0x68`.
* ARM64 DWARF compact-unwind rows now retain only live `__eh_frame` FDEs, serialize their final
  CIE/FDE records, and rewrite the compact-unwind low 24-bit FDE offsets. The serializer supports
  the Rust-produced DWARF32 `zR` / `zPLR` CIE grammar with an indirect PC-relative personality
  pointer; for a local personality it adds the required validated chained GOT rebase. Permanent
`macho/rust-panic-unwind` runs Rust `panic=unwind` / `catch_unwind` with `-dead_strip`.

### Dated-nightly Cargo corpus and self-host check

The retained synthetic Cargo workspaces are deliberately small. A separate, disposable corpus
was run with the exact `nightly-2026-07-24` toolchain, fresh per-project target directories, and
`-C linker=clang -C link-arg=--ld-path=<Wild> -C link-arg=-v`. Each passing final transcript
selected Wild and `-arch arm64`. The `regex 1.13.1` control builds and prints its successful
match/capture; `clap` derive builds and executes its parsed-value CLI; Tokio's loopback runtime
builds and runs through the SDK's `libiconv.tbd`; an `cc` build-script C++ client and a Security
framework client both build and run. The previous regex failure became the permanent
`macho/cstring-local-symbol-identity` regression; the previous Tokio link failure became the
permanent `macho/sdk-libiconv-external-reexport` regression. Corpus directories are intentionally
ephemeral because Cargo fingerprints and absolute paths are not durable test inputs.

Self-hosting was also run in an isolated temporary target directory. A dated-nightly baseline
Wild built a fresh Wild with `clang --ld-path=<baseline Wild> -v`; Clang's final child command
named the baseline ARM64 Wild binary. The resulting `MH_EXECUTE` carries `LC_MAIN`, chained
fixups, and a valid strict ad-hoc code signature. The integration test executable compiled in the
self-host target embeds that self-hosted Wild path and passed all 61 ARM64 Mach-O integrations.
This is a strong regression check, not a Rust compiler-bootstrap result.

An isolated Rust bootstrap used the exact source commit behind the requested toolchain,
`89c61a7545da48b06116675b888398d02a4064c7`, with ARM64 host/target, Xcode Clang, and a Wild
`--ld-path` recorded in each rebuilt rustc invocation. The source tree's legacy
`-Zno-embed-metadata` requires Rust's downloaded stage0 Cargo 1.98.0-beta.2 as the bootstrap
driver; it still uses the requested `nightly-2026-07-24` rustc/rustdoc. Apple and Wild controls
both built stage1 `library/core`. Wild then rebuilt stage1 `rustc_driver`, `compiler/rustc`, and
`src/tools/rustdoc`; their saved final-link replays and verbose logs name the current Wild binary.
The resulting ARM64 stage1 `rustc` and `rustdoc` both execute (`rustc 1.99.0-dev` and
`rustdoc 1.99.0-dev`), and rustc reports `MACOSX_DEPLOYMENT_TARGET=11.0` for ARM64.

This bootstrap initially crashed before target configuration because `-dead_strip` removed
`PassWrapper.cpp`'s `__mod_init_func` entry, leaving LLVM's `BBSectionsView` uninitialized.
`SectionHeader::should_retain` now roots the ABI-defined `S_MOD_INIT_FUNC_POINTERS` section type,
so its pointer relocation retains just the constructor atom; the permanent
`macho/cxx-init-dead-strip` dylib control returns 42 while its unrelated hidden atom remains
stripped. A subsequent stage1 rustdoc `SIGBUS` exposed a second issue: the export trie wrote a
local function's GOT-adjusted `raw_value`, making `std::io::stdio::stdout` point at
`__DATA_CONST,__got`. `macho_writer::export_symbol_address` now emits `symbol_address` for local
non-PLT definitions; `macho/dylib-export-local-got` proves a `dlsym` call reaches text while the
function also has a live GOT use. This remains a bounded stage1 bootstrap qualification, not a
full Rust distribution or compiler-test-suite claim.

One link-only performance replay used the same dated nightly and a saved `sizable-cli` Cargo
final link (Clap derive, regex, Serde, and serde_json): 48 replay files / 50.1 MiB and 46
object-or-archive arguments. On this M1 Pro (10 cores, 32 GiB, macOS 26.5.2), rotating 15-sample
wall-clock measurements had min/median/mean/max milliseconds of Apple ld64 1267:
135.368/145.258/155.662/212.253; ld64.lld 22.1.8:
99.108/109.214/113.753/153.635; and Wild:
127.857/142.855/149.300/193.012. Each ARM64 output passed the same runtime JSON/regex check;
sizes were 2,771,312 / 2,794,720 / 3,636,348 bytes respectively. The replay is retained under
`/tmp/wild-macho-performance.EnGAT0`. Earlier grouped repetitions had substantial ordering
sensitivity, `/tmp` is APFS, and thermal state was uncontrolled, so this is preliminary one-
workload evidence—not a speed or general-performance claim.

## Deferred / deliberately unsupported today

* Apple platforms other than macOS.
* Universal/fat output (thin binaries combined externally are sufficient).
* Incremental linking.
* x86_64 Mach-O is outside the agreed scope for this effort.
* C++/Objective-C/Rust/archived/split-DWARF dSYM debug maps and generic output-DWARF relocation.
* Objective-C selector forms other than ARM64 `_objc_msgSend$<selector>`, including selector-stub
  range-extension islands and `-const_selrefs` output placement.

## Next work items

1. Broaden final `__TEXT,__eh_frame` CIE/FDE grammar and qualify C++/Objective-C/Rust/archive
   debug-map inputs before designing any generic ordinary-DWARF relocation path.
2. Broaden subtractor coverage beyond the validated ordinary 64-bit static data form, and expand
   the bounded dylib/proc-macro and Rust TLS qualification.
3. Expand the Apple-differential corpus and ARM64 Rust crate-type/stress qualification.
