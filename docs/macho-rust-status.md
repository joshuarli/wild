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
| Secondary target | `x86_64-apple-darwin`, not yet implemented |
| Apple toolchain | Apple clang 21.0.0; ld64 1267; Homebrew `ld64.lld` present |

## Current phase

Phase 1–10: baseline, architecture audit, recorder infrastructure, and the first bounded
Mach-O semantic implementations. The repository's existing macOS CI job builds the workspace
and runs `cargo test --profile ci --workspace --features macho`; it is the existing fast Mach-O
regression entry point. This remains a regression gate, not production qualification.

Baseline checks completed on this host:

* `cargo build --profile ci --workspace --no-default-features` — pass.
* `WILD_TEST_IGNORE_FORMAT=1 cargo test --profile ci --workspace --features macho` — pass
  (170 `libwild` tests, 24 Mach-O integration tests, recorder tests, and remaining workspace/doc
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
| Mach-O argument semantics | Models ARM64, dylib/executable, install names, rpaths, export lists, framework paths, and strip options. `-dead_strip` currently uses section-level generic GC only. | partial; atom GC unqualified |
| Section/symbol classification | Handles data access, debug/non-alloc, `__DATA_CONST`, TLV storage, no-dead-strip, C strings, and Mach-O-specific no-op hooks. | partial |
| ARM64 relocations / thunks | Validates supported standalone forms and handles `POINTER_TO_GOT`; paired, TLVP, authenticated, and branch-island paths are explicitly diagnosed or absent. | partial; unqualified |
| Chained fixups | `libwild/src/macho_writer.rs` documents a one-page limitation and asserts the corresponding import limit. | unqualified |
| Dylib output / rpaths / exports | Emits `MH_DYLIB`, `LC_ID_DYLIB`, requested `LC_RPATH`, and omits executable-only commands; C runtime smoke passes. Dependency ordinals, weak/reexport behavior, and Rust dylib qualification remain. | partial; unqualified |
| Dead strip / atoms | `-dead_strip` is not yet wired to the generic liveness model. | unqualified |
| TLS, compact unwind, DWARF, string merging | No end-to-end qualification exists. | unqualified |
| x86_64 Mach-O | File-kind detection rejects non-ARM64 input. | not started |

## Compatibility matrix

| Facility | Minimal fixture | Apple differential | Rust integration | Stress test | Status |
| --- | --- | --- | --- | --- | --- |
| ARM64 executable | existing `wild/tests/sources/macho/trivial` | pending | pending | n/a | baseline only |
| SDK `.tbd` / libSystem | existing `trivial-libsystem` | pending | pending | n/a | baseline only |
| dylib | `trivial-dynamic` now links its `foo.c` dylib with Wild and consumes it at runtime | pass | C runtime pass | n/a | smoke green |
| framework | none | pending | pending | n/a | unqualified |
| dead strip | none | pending | pending | pending | unqualified |
| TLS | none | pending | pending | pending | unqualified |
| compact unwind | none | pending | pending | pending | unqualified |
| DWARF / dSYM / LLDB | none | pending | pending | pending | unqualified |
| chained fixups | existing output inspection only | pending | pending | pending | unqualified |
| branch islands | none | pending | pending | pending | unqualified |

## Reproducers and qualification commands

* Fast existing Mach-O suite: `cargo test --profile ci --workspace --features macho`.
* Existing CI build: `cargo build --profile ci --workspace --no-default-features`.
* Rust-to-Darwin command capture: [`darwin-linker-recorder.md`](darwin-linker-recorder.md)
  documents the new `darwin-linker-recorder` wrapper and its exact NUL-delimited replay records.
* Every future Rust/Cargo qualification must record the exact linker argv, working directory,
  SDK path, toolchain version, and proof that Wild performed the final link. No Apple-linker
  fallback is accepted as a passing Wild qualification.

### Unresolved correctness reproducer: ordinary Rust TLS/TLVP

An otherwise empty current stable Cargo binary already pulls in Rust runtime TLS and requires
`ARM64_RELOC_TLVP_LOAD_PAGEOFF12`. This is intentionally diagnosed rather than linked incorrectly.
On the baseline host, the following fails during the final Wild link with
`ARM64_RELOC_TLVP_LOAD_PAGEOFF12 requires Mach-O TLVP support`:

```sh
cargo build -p wild-linker --features macho --bin wild
scratch="$(mktemp -d)"
cargo init --bin --name wild_macho_smoke "$scratch"
RUSTFLAGS="-C linker=clang -C link-arg=--ld-path=$PWD/target/debug/wild" \
  cargo run --manifest-path "$scratch/Cargo.toml"
```

The failed link is evidence that the invocation selects Wild; it is not a fallback. The required
fix spans TLV section and descriptor layout, TLVP relocations, chained fixups, liveness, and
runtime behavior, so it remains the next foundational blocker for the Rust qualification path.

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
  supports both `ARM64_RELOC_POINTER_TO_GOT` representations, and reports paired/TLVP/arm64e
  forms explicitly instead of treating them as unknown or silently applying an invalid result.

## Deferred / deliberately unsupported today

* Apple platforms other than macOS.
* Universal/fat output (thin binaries combined externally are sufficient).
* Incremental linking.
* x86_64 Mach-O until ARM64 has an evidence-backed production qualification.

## Next work items

1. Implement end-to-end Mach-O TLS/TLVP (the first hard blocker for a current stable Rust binary),
   including descriptor layout, chained fixups, and runtime tests.
2. Generalize chained fixups and add branch islands; both need deterministic large-input fixtures.
3. Complete the Apple-differential corpus, framework/SDK validation, compact unwind, DWARF, and
   Rust crate-type qualification before beginning the x86_64 port.
