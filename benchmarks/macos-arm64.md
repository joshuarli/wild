# ARM64 macOS linker benchmark captures

This is the durable link-only benchmark protocol for `aarch64-apple-darwin`. It deliberately
contains no results: a benchmark result is publishable only when its saved replay inputs,
workload revision, toolchain, host/Xcode versions, and runner output have been retained together.
The seven names in [`macos-arm64.toml`](macos-arm64.toml) are the minimum workload matrix from
`plan.md` §30:

| Manifest key | Required capture |
| --- | --- |
| `tiny-rust-binary` | a small normal Rust executable |
| `medium-rust-project` | a representative multi-crate Cargo application |
| `proc-macro-heavy-workspace` | a workspace whose build invokes proc macros |
| `native-dependency-workspace` | a Rust workspace with a native C/C++ dependency final link |
| `large-rust-application` | a substantial Rust application final link |
| `wild` | Wild's own ARM64 executable link |
| `librustc-driver` | the substantial `rustc`/`rustc_driver` artifact link |

The manifest is intentionally complete. The runner rejects a save root with unlisted entries and
also rejects a manifest entry whose `run-with` capture is missing. Do not publish a partial run as
if it were the required matrix; use `--benches` only for development or a clearly labelled subset.

## Capture a real link

Use both capture mechanisms below. The recorder preserves the original Apple-driver contract;
the Wild save-dir makes that exact resolved input set replayable by the benchmark runner. Keep both
beside the workload revision rather than relying on a temporary path.

```sh
repo=/absolute/path/to/wild
captures=/durable/path/macos-arm64-captures
workload=/absolute/path/to/the/workload
wild="$repo/target/ci/wild"
recorder="$repo/target/ci/darwin-linker-recorder"

cargo +nightly-2026-07-24 build --profile ci -p wild-linker \
  --bin wild --bin darwin-linker-recorder
mkdir -p "$captures/recorder" "$captures/saves"
```

First record the unmodified Cargo link through Apple clang. This command is a capture operation,
not a Wild qualification or benchmark result.

```sh
cd "$workload"
WILD_DARWIN_LINKER_RECORD_DIR="$captures/recorder" \
WILD_DARWIN_LINKER_DELEGATE="$(xcrun --find clang)" \
CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER="$recorder" \
cargo +nightly-2026-07-24 build --target aarch64-apple-darwin --release
```

Then repeat the same workload/revision with Wild selected explicitly and save every resolved linker
input. Do not modify Rust, Cargo, or the workload merely to make a replay work.

```sh
WILD_SAVE_BASE="$captures/saves/raw" \
RUSTFLAGS="-C linker=clang -C link-arg=--ld-path=$wild" \
cargo +nightly-2026-07-24 build --target aarch64-apple-darwin --release
```

Select the final link deliberately. A Cargo build also saves build-script and proc-macro links, so
inspect each `run-with` script's `# Original output file:` footer and copy the selected complete
save directory to the manifest key, for example:

```sh
rg -n 'Original output file' "$captures/saves/raw"/*/run-with
cp -R "$captures/saves/raw/<selected>" "$captures/saves/tiny-rust-binary"
test -f "$captures/saves/tiny-rust-binary/run-with"
```

For every promoted capture, retain a `metadata.md` next to its `run-with` file with: workload URL
and immutable revision, Cargo command, `Cargo.lock` hash, rustc and Cargo versions, macOS/CPU/RAM,
Xcode/SDK versions, `wild --version`, `ld -v`, `ld64.lld --version`, the original recorder
directory, and a checksum/tree listing of the save directory. This avoids treating a moving
toolchain or a stale copied object as the same benchmark.

Before measurement, replay the chosen `run-with` once with each linker and confirm that all three
write and run/validate the intended output for that workload. A recorder capture delegates to
Apple clang and is never proof that Wild performed the final link; the explicit replay is that
proof.

## Measure one identical replay set

Set the three ARM64 linker binaries explicitly. `ld64.lld` is commonly supplied by Homebrew LLVM;
use the actual local path rather than assuming this example location.

```sh
apple_ld="$(xcrun --find ld)"
lld="/opt/homebrew/opt/llvm/bin/ld64.lld"
wild="/absolute/path/to/wild/target/ci/wild"
saves=/durable/path/macos-arm64-captures/saves
out=/durable/path/macos-arm64-output/link.out
mkdir -p "$(dirname "$out")"
```

Collect 15 warm link-only time/output-size samples per linker with the runner's Apple ld64,
wall-time, CPU, RSS, and output-size support. `--no-mem` avoids mixing Wild's `--no-fork` resource
samples into the normal-link wall-time series.

```sh
cargo +nightly-2026-07-24 run -p benchmark-runner -- bench \
  --config benchmarks/macos-arm64.toml \
  --saves "$saves" \
  --tmp "$out" \
  --allow-non-tmpfs \
  --no-mem \
  --batch-size 1 \
  --num-batches 15 \
  --output "$saves/macos-arm64-wall.bench-results" \
  --print-stats \
  "$apple_ld" "$lld" "$wild"
```

macOS normally reports APFS rather than Linux `tmpfs`; `--allow-non-tmpfs` is therefore an explicit
method choice, not a claim that output storage is memory-backed. Record the filesystem type, free
space, power mode, background workload, and thermal conditions with the result. The runner warms
each replay once before collecting batches.

Measure resource usage separately so every Wild run uses `--no-fork`, while Apple ld64 and ld64.lld
receive no unsupported flag. One 15-run first batch gives comparable link-process user CPU, system
CPU, and peak RSS samples without contaminating the normal-link wall-time series.

```sh
cargo +nightly-2026-07-24 run -p benchmark-runner -- bench \
  --config benchmarks/macos-arm64.toml \
  --saves "$saves" \
  --tmp "$out" \
  --allow-non-tmpfs \
  --batch-size 15 \
  --num-batches 1 \
  --output "$saves/macos-arm64-resources.bench-results" \
  --print-stats \
  "$apple_ld" "$lld" "$wild"
```

Keep the two result files and their `--print-stats` transcripts. Publish wall-time and output-size
from the first run; publish user CPU, system CPU, and peak RSS from the second. A result that has
not verified all three linkers for the same saved inputs is a failed/partial capture, not a
comparison. Do not calculate or state a speedup until the retained measurements support it.

## Scope and current evidence

This protocol measures only final link replay time. Full Cargo build time is a separate metric and
must not be used to hide or claim a link-time improvement. It does not add incremental linking.
The repository currently has a historical, one-workload ARM64 timing observation documented in
`docs/macho-rust-status.md`; its inputs lived under `/tmp` and it is not a durable manifest capture
or evidence for the full matrix above.
