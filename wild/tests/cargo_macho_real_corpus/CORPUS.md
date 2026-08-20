# ARM64 Cargo Mach-O corpus

This pinned workspace is the extended real-world qualification corpus for the Wild ARM64
Mach-O linker. It intentionally keeps runtime behavior local and deterministic so the same
locked graph can be built offline after its registry cache has been populated.

The workspace currently exercises four final Rust executable links:

* `cli-regex`: `clap` derive/proc-macro expansion, `regex`, `serde` derive, and JSON output.
* `async-network`: Tokio runtime, async TCP loopback, and async test harnesses.
* `git2-cli`: a repository create/index/tree/commit/read workflow through `git2`; its
  `libgit2-sys` dependency builds the vendored native C archive.
* `native-cpp`: a build-script-produced C++ static archive called from Rust.

The qualification harness runs `cargo clean`, `cargo build`, and `cargo test --workspace`
with `--locked` for both `stable` and `nightly-2026-07-24`, using a fresh target directory for
each compiler. It requires macOS ARM64 and enables the harness with
`WILD_RUN_MACHO_REAL_CARGO_CORPUS=1`.

To refresh the lockfile when intentionally changing dependencies, use the pinned nightly and
the populated registry cache, then review the complete diff:

```text
cargo +nightly-2026-07-24 generate-lockfile --offline
```
