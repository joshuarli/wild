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

The bounded ARM64 production qualification is complete. It includes the fast regression suite,
a disposable stable/nightly real-Cargo corpus, a self-host build, a bounded stage1 Rust bootstrap,
one contemporary Darwin run-make link, and a seven-workload Apple-ld64/LLD/Wild replay matrix.
The matrix is a correctness-qualified performance baseline, not a speed claim: Wild currently
loses substantially on the large Rust links, which identifies the next optimization work without
weakening the completed format contract.
The repository's ARM64 macOS CI job installs `nightly-2026-07-24` with `rust-src` and
`llvm-tools`, then explicitly runs `cargo +nightly-2026-07-24 build/test --profile ci --workspace
--features macho`. Stable coverage remains in the Linux jobs. The separate manual/scheduled
qualification workflow runs the larger corpus and self-host path without making ordinary pull
requests wait for them.

Baseline checks completed on this host:

* `cargo build --profile ci --workspace --no-default-features` — pass.
* `WILD_TEST_IGNORE_FORMAT=1 cargo +1.97.1-aarch64-apple-darwin test --profile ci --workspace
  --features macho` — pass (all workspace unit tests and doctests, including 224 `libwild` tests
  and 97 ARM64 Mach-O integrations).
* `WILD_TEST_IGNORE_FORMAT=1 cargo +nightly-2026-07-24 test --profile ci --workspace --features
  macho` — pass (all workspace unit tests and doctests, including 224 `libwild` tests and 97
  ARM64 Mach-O integrations). This is the reproducible dated-nightly gate; it is run with the
  installed `rust-src` and `llvm-tools` components, not by falling back to stable Rust.
* Without `WILD_TEST_IGNORE_FORMAT=1`, only tidy tests fail because this host lacks `taplo` and
  `clang-format`; this is the same exemption configured for the macOS CI job. No formatter or
  linter was run as part of this work.
* The existing Wild output for `trivial.c` is a valid signed ARM64 `MH_EXECUTE`; `codesign -dv`
  confirms its embedded ad-hoc signature. This is an executable smoke result, not a production
  qualification result.

## Evidence and current limits

The following table records the qualified ARM64 contract and its deliberate format boundaries.
`partial` means that the listed bounded behavior is green while a broader, explicitly diagnosed or
unqualified format family remains outside the current contract; it does not mean a silent fallback
or a known failure in the named workflow.

| Facility | Evidence | Status |
| --- | --- | --- |
| Mach-O argument semantics | Models ARM64, dylib/executable, install names, rpaths, export lists, framework paths, strip options, input-local `-force_load`, and `-dead_strip_dylibs` without removing dyld-required libSystem. | partial |
| Section/symbol classification | Carries section-derived function/TLS facts beside raw nlists, handles data access, debug/non-alloc, `__DATA_CONST`, TLV storage, no-dead-strip, C strings, and Mach-O-specific no-op hooks. `__thread_bss` extends its containing `__DATA` segment, unlike ELF's `PT_TLS`-only zero-fill convention. | partial |
| ABI-level symbols | Bounded ARM64 fixtures cover tentative/common `N_UNDF` definitions (size and `n_desc` alignment in `__DATA,__common`), direct `N_INDR` aliases, `N_PEXT` visibility, hidden synthetic `___dso_handle`, C++ initialization/`atexit`/destruction, and Rust calling a native C function. Weak dylib imports retain `N_WEAK_REF` separately from weak definitions: all-weak dependencies use `LC_LOAD_WEAK_DYLIB` and the chained-import weak bit, while an unprovided weak import remains an undefined-symbol error. Absolute symbols, alias chains, and broad mixed-language qualification remain outside this bounded result. | partial; focused Apple controls and Wild runtime/structural fixtures green |
| ARM64 relocations / thunks | Validates supported standalone forms, `POINTER_TO_GOT`, local and dylib-imported TLVP descriptors, paired `ADDEND`, bounded ordinary-data `SUBTRACTOR`/`UNSIGNED` expressions, and out-of-range `BRANCH26` via nearby text islands. Authenticated paths remain explicitly diagnosed or absent. | partial; unqualified |
| Chained fixups | Plans address-ordered imported binds and local rebases per segment; gaps, leading local slots, 16 KiB pages, and malformed encodings are handled. `macho/chained-fixups-multipage` executes 2300 imported `__got` binds across two pages, while `macho/chained-fixups-tlvp` executes two imported descriptor binds in `__thread_ptrs`. Wider pointer-format/arm64e qualification remains. | partial; bounded ARM64 runtime green |
| Dylib output / rpaths / exports | Emits `MH_DYLIB`, `LC_ID_DYLIB`, requested `LC_RPATH`, and omits executable-only commands. Undefined nlists owned by input dylibs remain dyld imports rather than being recursively rejected by the static link. Supported ARM64 output is always `MH_TWOLEVEL`: flat/interposable namespace modes are rejected, and a dylib self-reference stays bound to its own ordinal. C and bounded Rust `dylib` producer/consumer runtime controls pass. Dependency ordinals and weak/reexport behavior remain. | partial; bounded C/Rust dylib runtime green |
| Dead strip / atoms | `MH_SUBSECTIONS_VIA_SYMBOLS` inputs are split into live symbol-delimited spans under `-dead_strip`; whole-section behavior is retained otherwise. | partial; differential smoke green |
| TLS, compact unwind, DWARF, string merging | A local C TLS descriptor fixture executes successfully. ARM64 compact frame/frameless rows, personality pointers, and LSDAs are synthesized and a C++ throw/catch fixture passes. Bounded ARM64 DWARF-mode rows now serialize their live `__eh_frame` CIE/FDE records and pass a Rust `panic=unwind` / `catch_unwind` smoke under `-dead_strip`. Ordinary C, controlled C++14 and Objective-C loose objects, plus a normal Rust executable from `nightly-2026-07-24`, are represented only by bounded `dsymutil` debug maps; final executables intentionally do not copy `__DWARF`. | partial; bounded unwind and C/C++/Objective-C/Rust debug-map smoke green |

## Compatibility matrix

| Facility | Minimal fixture | Apple differential | Rust integration | Stress test | Status |
| --- | --- | --- | --- | --- | --- |
| ARM64 executable | existing `wild/tests/sources/macho/trivial` | pending | fresh stable Cargo bin and default `cargo test` link and run | n/a | smoke green |
| same-path code signing | `macho/code-signature-same-path-stress` | Apple links the baseline executable | n/a | Wild grows and shrinks one output path four times with a 2 MiB payload; every generation passes strict `codesign`, runs, and has a new inode | bounded ARM64 signing/relink green |
| SDK `.tbd` / libSystem | `macho/sdk-libcompression` links a versionless SDK TBD and runs; `macho/sdk-accelerate-nested-reexport` resolves an in-file Accelerate → vecLib → BLAS export; `macho/sdk-libiconv-external-reexport` resolves libiconv's separate libcharset child while retaining only libiconv in the consumer | Apple controls and Wild runtime/load-command assertions pass | pending | n/a | bounded ARM64 SDK-stub support |
| dylib | `trivial-dynamic` links its `foo.c` dylib with Wild; `macho/dylib-install-name-consumer` consumes an Apple-built physical-name mismatch through its `LC_ID_DYLIB`; `macho/aarch64/dylib-dependency-chain/default` links an executable → middle dylib → leaf dylib chain | Apple control, load-command assertions, and C runtime pass | retained Cargo Rust `dylib` producer/consumer links each final artifact through Wild and loads through `@loader_path` rpath | n/a | bounded C/Rust dylib runtime green |
| proc macro | `cargo_macho_macro_producer` expands through `TokenStream::from_str` into `40 + 2` | Apple control builds the producer/consumer pair | retained Cargo producer and consumer final links select Wild; the consumer runs the non-identity expansion | n/a | bounded ARM64 Cargo proc-macro runtime green |
| framework | `macho/framework-security` calls `SecRandomCopyBytes`; `framework-corefoundation` imports a constant and functions through `-framework CoreFoundation`; `rust-framework-security` uses Rust `#[link(kind = "framework")]` | Apple controls and Wild output carry the current SDK framework load commands; all run successfully | C Security/CoreFoundation and exact-nightly Rust Security consumers run through Wild | n/a | bounded ARM64 framework runtime/structural green |
| Objective-C selector dispatch | `macho/objc-runtime`, `objc-multi-selector`, `objc-const-selrefs`, and `objc-dead-selector` compile normal ARC calls without compiler workarounds | Apple ld establishes one 32-byte `__objc_stubs` veneer and one chained-rebase `__objc_selrefs` slot per live selector; `-const_selrefs` instead uses regular `__DATA_CONST` storage | n/a | repeated selectors deduplicate lexically; a dead selector atom emits neither synthetic section | bounded ARM64 Objective-C runtime green |
| dead strip | `macho/dead-strip` | code/data/export parity pass | C runtime pass | `macho/dead-strip-10000` strips 9,999 of 10,000 symbol-delimited text atoms | ARM64 atom GC green |
| ABI-level symbols | `macho/common-symbols`, `symbol-aliases`, `weak-symbols`, `weak-undefined`, `cxx-init-teardown` | Apple controls establish common/alias/weak behavior | `macho/rust-native-ffi` calls C through Wild | pending | bounded C/C++/Rust smoke green |
| TLS | `macho/tls-local`, `tls-dynamic`, `cxx-thread-local`, `cxx-thread-local-dylib`, `rust-thread-local`, and Cargo's Rust-dylib producer/consumer | Apple ld binds the imported descriptor through `__got`; ld64.lld uses `__thread_ptrs` | C, C++, a Rust executable, and a dynamically loaded Rust `dylib` prove two-thread isolation under Wild | pending | bounded C/C++/Rust local/dylib smoke green |
| compact unwind | `macho/exception`, `cxx-exception-cleanup` C++ throw/catch and RAII cleanup; `rust-panic-unwind`, `rust-cxx-unwind-bridge` | structural section/header check; C++ and Rust runtime pass | ARM64 Rust `panic=unwind` / `catch_unwind`, including Rust → C++ RAII → Rust under the dated nightly | pending | bounded ARM64 support |
| DWARF / dSYM / LLDB | `macho/debug-dwarf`, `cxx-debug-dwarf`, `objc-debug-dwarf`, `strip-symbols`, and Rust `rust-debug-dwarf` / `rust-debuginfo-line-tables` / `rust-split-debug-dwarf` / `rust-split-debug-packed` | Apple ld and ld64.lld establish the same `N_SO`/`N_OSO`/paired-`N_FUN` control shape; `-S` / `-s` links run, and Wild `dsymutil --dump-debug-map` passes | generated dSYMs verify; LLDB stops at C, C++14, Objective-C, normal Rust, Rust `debuginfo=1`, and Rust `split-debuginfo=unpacked` / `packed` source locations (Rust uses `nightly-2026-07-24`) | pending | bounded loose-object ARM64 C/C++/Objective-C/Rust support |
| chained fixups | `macho/chained-fixups-tlvp`, `chained-fixups-multipage`, `chained-fixups-10000` | Apple controls and Wild runtime pass | pending | 10,000 imported `__got` binds cross five 16 KiB pages; two imported `__thread_ptrs` binds exercise a non-zero TLVP page offset | bounded ARM64 runtime green |
| branch islands | `macho/branch-island`, `macho/branch-island-call`, `macho/branch-islands` | Apple links forced `B` and `BL` overflows | C runtime pass | multiple islands pass | ARM64 smoke green |
| malformed input diagnostics | malformed object/TBD/export-list unit controls plus `macho/missing-library`, `missing-framework`, `undefined-symbol`, and relocation/argument controls | n/a | n/a | n/a | malformed object/TBD/export-list input is rejected before layout; missing dependencies and supported negative controls diagnose rather than panic |

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
| C/Rust SDK frameworks | permanent `macho/framework-security`, `framework-corefoundation`, and exact-nightly `macho/rust-framework-security` exercise C Security/CoreFoundation and Rust Security imports under Wild; Security asserts the SDK install name/version | broaden framework search-path and framework matrix |
| C dylib dependency chain | `macho/aarch64/dylib-dependency-chain/default` links the leaf, middle, and executable images separately with Apple ld and Wild; each output records its immediate `@rpath` dependency and the executable runs after both dyld rpath lookups with `DYLD_*` overrides removed | broaden dependency graph and reexport matrix |
| C/C++ local and dylib TLS | `macho/tls-local`, `cxx-thread-local`, `tls-dynamic`, and `cxx-thread-local-dylib` cover initialized and zero-fill native TLS, direct imported descriptor access, two-thread isolation, `-dead_strip`, and PIE/ASLR | broaden TLS/dylib coverage |
| Rust `cdylib` consumed from C | permanent `macho/rust-cdylib-consumer` replays rustc's `cdylib` link through Wild, exports a C ABI function, and runs from a C consumer | broaden Rust dylib/export and mixed-language coverage |
| Rust `staticlib` consumed from C++ | ARM64-only `macho/aarch64/cargo-staticlib-native/default` builds with `nightly-2026-07-24`, checks C ABI exports, and links/runs native C++ consumers through Apple and explicitly through Wild; one control throws in C++, crosses Rust `extern "C-unwind"`, and catches in C++ | broaden the ABI and exception-stress matrix; x86_64 remains out of scope |
| Rust `dylib` consumed from Rust | `macho/aarch64/cargo-workspace-qualification/default` links the producer and consumer through Wild, runs the consumer via its Mach-O rpath, and verifies state in the producer's `thread_local!` is initialized independently in a child thread | broaden dependency and TLS matrix |
| Proc macro crate | `macho/aarch64/cargo-workspace-qualification/default` links the proc-macro producer and consumer through Wild, loads the macro during compilation, and executes its non-identity expansion | broaden macro/crate stress coverage |
| Ordinary Cargo rebuilds | The same isolated workspace mutates a proc-macro consumer Rust source, a `build.rs`-tracked marker, and the Rust-dylib producer body in turn. Each transition must relink the expected ARM64 artifacts through Wild, replace the same output paths, and rerun successfully without `DYLD_*` search-path overrides. The retained fixture is checked unchanged afterward. | broaden dependency and build-script matrix |
| Rust `thread_local!` / `cargo test` | permanent `macho/rust-thread-local` and the Cargo Rust-`dylib` two-thread control pass through Wild; the latter is also invoked by `cargo test` | exercise staticlib and broader dylib TLS matrix |
| Rust optimized executable | exact-nightly `macho/rust-release` links and runs with `-O -C codegen-units=16`, while `macho/rust-lto` separately runs ThinLTO and fat LTO | broaden crate-scale and profile coverage |
| C++ throw/catch and cleanup | `macho/exception` catches, while `cxx-exception-cleanup` verifies a destructor runs through its LSDA landing pad; both emit `__TEXT,__unwind_info` and run | broaden compact-unwind differential coverage |
| Rust `panic=unwind` | `macho/rust-panic-unwind` selects live CIE/FDE records, rewrites DWARF compact-unwind FDE offsets, and catches a panic at runtime under `-dead_strip` | broaden CIE/FDE grammar and crate/stress coverage |
| Rust → C++ → Rust unwind | `macho/rust-cxx-unwind-bridge` panics through a C++ RAII frame and catches in Rust; its destructor increments the observed cleanup count | broaden cross-language unwind and ABI coverage |
| C/C++/Objective-C/Rust DWARF / `dsymutil` | `macho/debug-dwarf`, `cxx-debug-dwarf`, `objc-debug-dwarf`, `rust-debug-dwarf`, `rust-debuginfo-line-tables`, `rust-split-debug-dwarf`, and `rust-split-debug-packed` emit `N_SO`, `N_OSO`, and live-atom `N_FUN` pairs; `dsymutil` makes verified dSYMs and LLDB stops at their source lines under `-dead_strip` | qualify more language forms and debug-map inputs |
| `-dead_strip` and `-force_load` | dead C code/data and an unreferenced forced archive member are covered; `macho/dead-strip-10000` retains one of 10,000 symbol-delimited text atoms; `dead-strip-archive-atoms` strips dead atoms after lazy archive extraction | add relocation-target stress |
| `-dead_strip_dylibs` | `macho/dead-strip-dylibs` removes an unused dylib's install name while retaining `/usr/lib/libSystem.B.dylib`, which dyld requires for an executable | broaden dylib reachability cases |
| 138 MiB fragmented branch | Apple and Wild both link/run through nearby islands for both `B` and call/return `BL` forms | larger stress qualification |
| 10,000 imported data binds | `macho/chained-fixups-10000` runs after reading every `__got` slot across five 16 KiB pages; the smaller `chained-fixups-multipage` remains the focused two-page control | broaden segment/pointer-format and local-rebase coverage |
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
  workspace, executes its initial `build` and `test`, then mutates a proc-macro consumer, a
  `build.rs` input, and the dylib producer in a temporary copy. It audits every final ARM64 Clang
  invocation printed by `cargo -vv` for Wild's `--ld-path`, rejects x86_64 links, runs the
  rebuilt binaries without `DYLD_*` overrides, and confirms the retained fixture did not change.
* Focused C debug-map fixture: `WILD_TEST_IGNORE_FORMAT=1 cargo test --profile ci -p wild-linker
  --test integration_tests --features macho -- 'macho/aarch64/debug-dwarf/default'`. Its output
  can be checked with `dsymutil --dump-debug-map <binary>`, `dsymutil <binary>`, and
  `dwarfdump --verify <binary>.dSYM/Contents/Resources/DWARF/<binary-name>`.
* Focused Rust debug-map fixture: `WILD_TEST_IGNORE_FORMAT=1 cargo +nightly-2026-07-24 test
  --profile ci -p wild-linker --features macho --test integration_tests --
  'macho/aarch64/rust-debug-dwarf/default'`. It uses the exact dated toolchain independently of
  the harness default, checks that `-dead_strip` omits the private Rust atom, verifies its dSYM,
  and has LLDB stop in `wild_rust_debug_dwarf_add` at `rust-debug-dwarf.rs:14`.
* Focused C++14 and Objective-C debug-map fixtures: `WILD_TEST_IGNORE_FORMAT=1 cargo
  +nightly-2026-07-24 test --profile ci -p wild-linker --features macho --test integration_tests
  -- 'macho/aarch64/cxx-debug-dwarf/default'` and the same command with
  `macho/aarch64/objc-debug-dwarf/default`. Each proves Apple ld, ld64.lld, and Wild produce a
  valid dSYM and that LLDB stops at the named source-level helper; the former deliberately emits
  only `DW_LANG_C_plus_plus_14`, while the latter emits only `DW_LANG_ObjC`.
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
* The permanent ARM64 `macho/rust-lto` fixture uses `nightly-2026-07-24` to run both
  `-C lto=thin -C codegen-units=2` and `-C lto=fat -C codegen-units=1`. rustc passes
  `-lto_library` even though ordinary LTO has already produced native Mach-O objects, and both
  links run through Wild. In contrast, `-C linker-plugin-lto` adds `-plugin-opt=O0` and
  `-plugin-opt=mcpu=apple-m1`; Wild diagnoses that separate LLVM-bitcode linker-plugin contract
  explicitly rather than accepting the options and silently doing no LTO.

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

The trial creates one fresh short `/tmp` Cargo target directory for the copied workspace, then
invokes each package operation with `cargo +nightly-2026-07-24 build -vv` and
`cargo +nightly-2026-07-24 test -vv` using `clang --ld-path=<Wild>`, `-v`, and
`-C prefer-dynamic`. The fresh workspace target forces the initial producer, consumer, and test
links; later invocations deliberately exercise Cargo rebuild behavior. The explicit selector is
necessary because rustup chooses Cargo before it opens a nested workspace's `rust-toolchain.toml`.
The trial parses every final Clang link
transcript, requires that each expected producer and consumer artifact selected Wild, requires
`-arch arm64`, and rejects `x86_64`. The proc macro uses
`TokenStream::from_str("40 + 2")`, so the consumer proves that a loaded macro performed a
non-identity expansion. The Rust-dylib consumer is then executed after clearing the `DYLD_*`
library search overrides; `otool` additionally checks both its `@loader_path` rpath and its
`@rpath/libcargo_macho_dylib_producer.dylib` dependency. The producer also owns a
`thread_local!` cell: the consumer mutates it on the main thread, calls into the same dylib from a
child Rust thread, and proves that the child starts at 40 without changing the main thread's 41.
It also invokes `cargo test -vv` for that consumer: Cargo executes its dylib-dependent
unit-test harness, including the same two-thread TLS contract, and the trial separately audits
both the harness and test-mode producer final ARM64 links through Wild. The trial then copies the
retained workspace into its temporary directory, changes only the copied dylib producer
implementation body while preserving its API and result, and rebuilds/runs the dylib consumer.
Its second transcript again requires both producer and consumer final ARM64 links through Wild; a
snapshot asserts that every retained fixture Rust source is unchanged. This coverage deliberately
does not use `WILD_SAVE_DIR` or the `cdylib` replay path above.

The same workspace was also rebuilt in a fresh target directory with the recorded stable
`1.97.1` toolchain, `clang --ld-path=<Wild> -v`, and `-C prefer-dynamic`. The proc-macro
consumer's ordinary `cargo run` completed its non-identity expansion, and the Rust-dylib
consumer's ordinary `cargo test` completed its two-thread TLS assertion. Their printed final
Clang commands named Wild and `-arch arm64`; this is an additional compatibility confirmation,
while the permanent harness continues to pin the requested dated nightly.

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
`__TEXT,__objc_stubs` entry plus one `__DATA,__objc_selrefs` slot per distinct selector. With
`-const_selrefs`, `MachOArgs::const_selrefs` instead selects a regular zero-flag
`__DATA_CONST,__objc_selrefs` section, matching ld64's post-fixup read-only contract.
`macho_writer::write_objc_message_stubs` emits ld64's fixed
`ADRP/LDR x1; ADRP/LDR x16; BR; BRK*3` veneer and adds the selector slot to the local chained
rebase plan. The selector is found through the final merged `__objc_methname` map, so identical
strings from different objects cannot retain stale input addresses.

`macho/objc-runtime` proves normal ARC dispatch through `NSObject` with the current SDK TAPI
`objc-classes` field materialized as class and metaclass symbols. `objc-multi-selector` proves
the 32-byte/8-byte-per-selector layout, lexical deduplication, and runtime dispatch; the minimal
assembler `objc-dead-selector` proves dead selector branches do not create output sections.
`objc-const-selrefs` proves normal ARC dispatch while asserting the 8-byte selector slot belongs
to `__DATA_CONST` and carries ld64's regular-section flags.
This is deliberately limited to Clang's `_objc_msgSend$<nonempty-selector>` ARM64 form. It does
not claim a generic Objective-C metadata linker, selector-stub branch islands, or Objective-C
dSYM support beyond the separately controlled loose-object `DW_LANG_ObjC` map.

### Bounded C/C++/Objective-C/Rust `dsymutil` debug maps

`macho/debug-dwarf` is the permanent ARM64 C control; `macho/cxx-debug-dwarf` is the explicit
C++14 control; `macho/objc-debug-dwarf` is the normal Objective-C control; and
`macho/rust-debug-dwarf`, `macho/rust-debuginfo-line-tables`,
`macho/rust-split-debug-dwarf`, and `macho/rust-split-debug-packed` are normal Rust-executable
controls compiled with `nightly-2026-07-24`; the second uses `-C debuginfo=1`, and the last two
use `-C split-debuginfo=unpacked` and `packed` respectively. Each supplies one loose debug object
and links with `-dead_strip`. Wild
intentionally leaves final `__DWARF` sections out of the executable, as Apple ld and ld64.lld do.
Instead `MachO::allocate_object_symtab_space` reserves, and `write_dsymutil_debug_map` emits,
`N_SO`, `N_OSO`, one start/terminator `N_FUN` pair for each live executable atom, and the
terminating empty `N_SO`. Start addresses use the post-GC compacted section mapping; terminators
retain each atom's original input length. `dsymutil` owns DWARF relocation and address rewriting
when it builds the dSYM.

The supported input is deliberately small: a loose ARM64 Mach-O object with
`MH_SUBSECTIONS_VIA_SYMBOLS`, ordinary C (`DW_LANG_C89`, `C`, `C99`, `C11`, or `C17`), Rust
(`DW_LANG_Rust`), explicitly `-std=c++14` C++ (`DW_LANG_C_plus_plus_14`), or Objective-C
(`DW_LANG_ObjC`) debug data, and live, non-merged executable atoms. Every fixture checks that a
dead private function is absent from the map, runs `dsymutil --dump-debug-map`, verifies the
generated dSYM with `dwarfdump`, and uses an LLDB batch source breakpoint. Other C++ and
Objective-C language forms (including Objective-C++), archives, split-debug modes other than the
controlled Rust `unpacked`/`packed` forms, Rust library/dylib debug maps, and Rust modes other
than the controlled normal `debuginfo=1`/default executables remain unclaimed. There is no final-
section copy or generic debug relocation writer hidden behind these controls.

`macho/strip-symbols` separately exercises direct ld64 `-S` and `-s` commands. `-S` suppresses
the debug map, while `-s` must still produce a runnable output even though layout reserves no
ordinary Wild nlist/string-table space. Its original Wild failure was a `write_symbols` attempt
to consume that intentional zero allocation; the writer now skips all nlist serialization when
`MachOArgs::should_strip_all()` is true.

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
* Rust's unconditional `-lto_library` is recognized only as the no-op native-object ld64
  contract it is for ordinary Rust LTO. `macho/rust-lto` permanently runs both ThinLTO and fat
  LTO through the exact dated nightly. Rust `-C linker-plugin-lto` reaches the separately
  diagnosed `-plugin-opt` path, which names the unsupported ARM64 Mach-O LLVM-bitcode boundary.
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
* Every supported ARM64 output uses Mach-O's `MH_TWOLEVEL` namespace. Wild deliberately rejects
  `-flat_namespace`, `-force_flat_namespace`, and `-interposable`; it does not silently accept a
  lookup contract it cannot model. `macho/twolevel-self-binding` proves the resulting ordinal
  behavior: an executable's public definition returns 41 while a dylib self-call remains bound
  to the dylib's definition returning 1.
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
* Mach-O output replacement deliberately unlinks before writing a same-path successor so the
  kernel cannot reuse an executed vnode's cached code-signature state. The permanent
  `macho/code-signature-same-path-stress` test keeps every prior inode open, alternates a 2 MiB
  initialized payload into and out of one executable four times, and requires strict
  `codesign --verify` plus successful execution after every signed generation.
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
  distinct imported data binds across two `__DATA_CONST,__got` pages, while
  `macho/chained-fixups-10000` executes 10,000 across five pages. A dynamic TLVP remains an
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

The corpus also contains a deterministic `git2` CLI. Its `libgit2-sys` dependency compiles a
vendored archive from 260 native C sources before the final Rust link, then creates, indexes,
commits, and reads a local repository at runtime. Together with the existing Tokio TCP loopback,
Clap/Serde/regex derive graph, and `cc`-built C++ client, this gives the stable and
`nightly-2026-07-24` clean/build/test corpus real asynchronous, macro/codegen, native C, native
C++, framework, and substantial dependency-graph coverage. `CORPUS.md` beside the fixture
records the pinned/offline-refresh contract.

Self-hosting was also run in an isolated temporary target directory. A dated-nightly baseline
Wild built a fresh Wild with `clang --ld-path=<baseline Wild> -v`; Clang's final child command
named the baseline ARM64 Wild binary. The resulting `MH_EXECUTE` carries `LC_MAIN`, chained
fixups, and a valid strict ad-hoc code signature. The integration test executable compiled in the
self-host target embeds that self-hosted Wild path and passed all 97 ARM64 Mach-O integrations.
This is a strong regression check, distinct from the bootstrap result below.

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

One contemporary Darwin run-make recipe was also exercised through the requested nightly. The
nightly's installed source commit (`89c61a754`) is not currently fetchable from the upstream Rust
repository, so this used current Rust main (`f7d782a3`, 2026-08-19) only for
`tests/run-make/apple-c-available-links`, while `rustc 1.99.0-nightly (89c61a754 2026-07-23)`
remained the compiler and link driver. A disposable harness built the current recipe and its
`run-make-support` dependency, then ran its Apple control and an otherwise identical wrapper
that adds `-C linker=<Xcode clang> -C link-arg=--ld-path=<Wild>`. Both produced and executed an
ARM64 `main`; the Wild save-dir replay contains `-arch arm64`, the exact nightly `libstd`, and
the recipe's `foo.o`. This is one current Darwin run-make/link result, not an `x.py test` claim
for the unavailable dated source revision.

One historical link-only replay used the same dated nightly and a saved `sizable-cli` Cargo final
link (Clap derive, regex, Serde, and serde_json): 48 replay files / 50.1 MiB and 46
object-or-archive arguments. On this M1 Pro (10 cores, 32 GiB, macOS 26.5.2), rotating 15-sample
wall-clock measurements had min/median/mean/max milliseconds of Apple ld64 1267:
135.368/145.258/155.662/212.253; ld64.lld 22.1.8:
99.108/109.214/113.753/153.635; and Wild:
127.857/142.855/149.300/193.012. Each ARM64 output passed the same runtime JSON/regex check;
sizes were 2,771,312 / 2,794,720 / 3,636,348 bytes respectively. Its inputs lived under the
ephemeral `/tmp/wild-macho-performance.EnGAT0`, the capture did not retain the complete
user/system CPU and peak-RSS series, and earlier grouped repetitions had substantial ordering
sensitivity on APFS with uncontrolled thermal state. It is therefore a historical, preliminary
one-workload observation—not a speed or general-performance claim.

### Durable ARM64 link replay matrix

`benchmarks/macos-arm64.toml` and `benchmarks/macos-arm64.md` define the ARM64 link-only
capture/replay matrix. The provenance-refreshed run retained seven `run-with` saves, complete
copied-link-input manifests, all-3-linker verification output, a 15-sample warm wall series, and
a separate 15-sample resource series under
`/Users/josh/d/wild-benchmark-data/macos-arm64-2026-08-19/`. Every saved replay linked and its
output validated with Apple ld64 1267, Homebrew ld64.lld 22.1.8, and Wild `b24e8447` (the measured
worktree was dirty) before timing.

| Final-link replay | Apple ld64 median (ms) | LLD median (ms) | Wild median (ms) |
| --- | ---: | ---: | ---: |
| tiny Rust binary | 99.570 | 78.065 | 410.525 |
| medium Rust project | 113.256 | 95.359 | 475.042 |
| proc-macro-heavy workspace | 107.568 | 97.850 | 714.065 |
| native-dependency workspace | 109.905 | 82.200 | 397.822 |
| large Rust application | 272.657 | 393.646 | 7,598.271 |
| Wild self link | 277.757 | 446.270 | 27,108.415 |
| `librustc_driver` | 316.497 | 496.913 | 53,272.239 |

Wild's median user CPU / peak RSS for those rows was respectively 595.974 ms / 34.438 MiB,
795.555 / 43.719, 2,035.611 / 54.906, 596.730 / 35.828, 35,505.334 / 291.938,
72,176.532 / 1,413.609, and 217,191.976 / 468.219. The full per-linker resource TSV remains
beside the result files. This is an honest optimization baseline: Wild is currently materially
slower on every measured replay, particularly large Rust links; no speedup is claimed.

The baseline prompted a profile-driven Mach-O optimization before this status was closed. The
same retained `librustc_driver` replay took 86.14 seconds before and 56.52 seconds after caching
normalized relocation pairs once per input section during atom-GC traversal (34.4% end-to-end;
the `Traverse reference graph` phase fell from 49.85 to 22.72 seconds). The optimized output had
the same SHA-256 (`7d3e…3ced6`). This preserves a concrete before/after result without pretending
that one optimization erases the remaining large-link gap.

The provenance-refreshed artifacts are
`macos-arm64-{verification,wall,resources}-provenance-refreshed.{bench-results,log}` and their
corresponding `medians.tsv` files. The host was an M1 Pro with 32 GiB on macOS 26.5.2, on AC power
with Low Power Mode disabled; APFS was used with explicit `--allow-non-tmpfs`. Every save now has
an immutable source revision, command/toolchain/host notes, and a passing `tree.sha256` manifest.
The freshly promoted tiny/medium/proc-macro/native captures retain their original recorder details.
The large-app, Wild-self, and Rust-driver source/build provenance was recovered from retained
logs, but their original recorder executable/path/hash, delegate settings, and invocation status
were not recoverable; that limitation is recorded in their sidecars rather than guessed.

## Deferred / deliberately unsupported today

* Apple platforms other than macOS.
* Universal/fat output (thin binaries combined externally are sufficient).
* Incremental linking.
* x86_64 Mach-O is outside the agreed scope for this effort.
* C++ language forms other than controlled `DW_LANG_C_plus_plus_14`, Objective-C++ and other
  Objective-C language forms, archived and split-debug dSYM maps other than Rust's controlled
  `split-debuginfo=unpacked` / `packed` forms, Rust library/dylib and broader debug-info-mode maps, and
  generic output-DWARF relocation.
* Objective-C selector forms other than ARM64 `_objc_msgSend$<selector>`, including selector-stub
  range-extension islands.
* ARM64 Mach-O linker-plugin LTO (`-C linker-plugin-lto` and Rust's `-plugin-opt` arguments).
  Ordinary Rust `-C lto=thin` and `-C lto=fat` links, which hand Wild native ARM64 Mach-O objects,
  are separate supported workflows.
* Pre-bound `MH_OBJECT` inputs carrying `LC_DYSYMTAB` indirect-symbol sections
  (`S_NON_LAZY_SYMBOL_POINTERS`, lazy-pointer/stub variants, or
  `S_THREAD_LOCAL_VARIABLE_POINTERS`). Wild validates their table bounds and then rejects them:
  its ARM64 writer represents bindings through chained fixups and does not serialize the legacy
  indirect-symbol/lazy-bind contract. Supply the original relocatable producer input instead.

## Follow-up expansion work

1. Broaden final `__TEXT,__eh_frame` CIE/FDE grammar and qualify additional C++/Objective-C/Rust
   language forms plus archive debug-map inputs before designing any generic ordinary-DWARF
   relocation path.
2. Broaden subtractor coverage beyond the validated ordinary 64-bit static data form, and expand
   the bounded dylib/proc-macro and Rust TLS qualification.
3. Expand the Apple-differential corpus and ARM64 Rust crate-type/stress qualification.
