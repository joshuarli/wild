## Install

`~/.cargo/config.toml`

```toml
[target.aarch64-apple-darwin]
linker = "/usr/bin/clang"
rustflags = ["-Clink-arg=--ld-path=wild-arch64-apple-darwin"]

[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-Clink-arg=--ld-path=wild-x86_64-unknown-linux-gnu"]

[target.aarch64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-Clink-arg=--ld-path=wild-aarch64-unknown-linux-gnu"]
```

For a per-project setting, put the same block in that project's `.cargo/config.toml`. To opt in for
one command instead:

```sh
RUSTFLAGS="-C linker=clang -C link-arg=--ld-path=$(command -v wild)" cargo build
```

Keep Clang as Cargo's linker driver: it supplies the macOS SDK and system libraries. For a native
link, use the same pattern:

```sh
clang --ld-path="$(command -v wild)" hello.o -o hello
```

## Building from source (macos)

This is only needed when you want an unreleased version. It requires Rust 1.97.1 or later:

```sh
cargo build --release -p wild-linker --bin wild
```
