#!/bin/sh
# Run inside the native Alpine image. /work inputs are read-only mounts and /cache is the sole
# durable benchmark state, supplied by the caller as ~/.cache/wild/linux-aarch64-cargo.
set -eu

cache_root=${WILD_LINUX_BENCHMARK_CACHE_ROOT:-/cache}
case "$cache_root" in
    /cache|/cache/*) ;;
    *) echo "WILD_LINUX_BENCHMARK_CACHE_ROOT must stay below /cache" >&2; exit 2 ;;
esac

cache_cargo_home="$cache_root/cargo-home"
cache_wild_target="$cache_root/wild-build"
cache_workspaces="$cache_root/workspaces"
cache_reports="$cache_root/benchmarks"
report_id=${WILD_LINUX_BENCHMARK_REPORT_ID:-"cargo-linux-aarch64-$(date +%Y%m%d-%H%M%S)"}

mkdir -p "$cache_cargo_home" "$cache_wild_target" "$cache_workspaces" "$cache_reports"

export CARGO_HOME="$cache_cargo_home"
export CC=clang
export CXX=clang++

# Fetch before the measured runner. The runner itself is offline so samples never depend on
# network latency or mutate the source mounts.
cargo +nightly-2026-07-24 fetch --locked --manifest-path /work/wild/Cargo.toml
cargo +nightly-2026-07-24 fetch --locked --manifest-path /work/cargo/Cargo.toml

CARGO_TARGET_DIR="$cache_wild_target" \
    cargo +nightly-2026-07-24 build --locked --offline \
    --manifest-path /work/wild/Cargo.toml \
    --profile dist --target aarch64-unknown-linux-musl \
    -p wild-linker --bin wild --no-default-features --features fork

python3 /work/wild/benchmarks/cargo_linux_link_benchmark.py \
    --config /work/wild/benchmarks/cargo-linux-aarch64.benchmark.json \
    --workspace /work/cargo \
    --cargo "$(command -v cargo)" \
    --wild "$cache_wild_target/aarch64-unknown-linux-musl/dist/wild" \
    --scratch-root "$cache_workspaces" \
    --link-repetitions "${WILD_LINUX_LINK_REPETITIONS:-5}" \
    --resource-link-repetitions "${WILD_LINUX_RESOURCE_LINK_REPETITIONS:-1}" \
    --output "$cache_reports/$report_id.json" \
    "$@"
