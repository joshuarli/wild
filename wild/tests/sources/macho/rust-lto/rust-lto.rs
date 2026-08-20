//#AbstractConfig:base
//#Arch:aarch64
//#RustcToolchain:nightly-2026-07-24

//#Config:thin:base
//#CompArgs:-C lto=thin -C codegen-units=2

//#Config:fat:base
//#CompArgs:-C lto=fat -C codegen-units=1

// Rust's ordinary Darwin LTO modes hand the native linker final ARM64 Mach-O objects and the
// current `-lto_library` contract. Both modes must therefore link and run without treating that
// ld64 option as a request for unsupported linker-plugin bitcode processing.
#[inline(never)]
fn lto_leaf(value: i32) -> i32 {
    value + 2
}

#[inline(never)]
fn lto_middle(value: i32) -> i32 {
    lto_leaf(value)
}

fn main() {
    std::process::exit(if lto_middle(40) == 42 { 42 } else { 1 });
}
