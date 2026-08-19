# Darwin Rust linker-invocation recorder

`darwin-linker-recorder` is a transparent wrapper for collecting the actual argument contract
between current `rustc` and the Apple toolchain. It records an invocation, then delegates to the
Apple compiler driver unchanged. It is a conformance-laboratory tool, not a Wild fallback.

Build it with:

```sh
cargo build -p wild-linker --bin darwin-linker-recorder
```

Set both variables before pointing Cargo's target linker at the recorder:

```sh
export WILD_DARWIN_LINKER_RECORD_DIR="$PWD/target/darwin-link-recordings"
export WILD_DARWIN_LINKER_DELEGATE="$(xcrun --find clang)"
```

For a temporary capture, use a target-specific Cargo configuration such as:

```toml
[target.aarch64-apple-darwin]
linker = "/absolute/path/to/darwin-linker-recorder"
```

Each invocation creates `link-<pid>-<sequence>` below the selected record directory. It contains:

* `argv.nul` — exact, NUL-delimited argument bytes; use this as the replay source of truth.
* `metadata.txt` — the delegate executable and working directory.
* `environment.txt` — Darwin/Rust/Cargo variables relevant to linker behavior, intentionally
  limited to a non-secret allowlist.
* `inputs.txt` — a human-readable classification of object, archive, TBD, dylib, framework, and
  search-path arguments.
* `delegate-status.txt` — the delegate's final exit status.

The recorder deliberately fails if either environment variable is absent. A capture run delegates
to Apple clang so it must never be counted as evidence that Wild performed a final link. Use the
saved `argv.nul` only to construct equivalent Wild qualification runs, where the test's invocation
audit proves Wild was selected.
