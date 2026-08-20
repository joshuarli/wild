//#Arch:aarch64
//#RustcToolchain:nightly-2026-07-24
//#CompArgs:-O -C codegen-units=16

// Keep a normal optimized, multi-codegen-unit executable separate from the LTO fixture: Cargo
// release links routinely combine many native ARM64 object fragments without asking ld64 to run
// linker-plugin LTO.
#[inline(never)]
fn release_leaf(value: i32) -> i32 {
    value + 2
}

#[inline(never)]
fn release_middle(value: i32) -> i32 {
    release_leaf(value)
}

fn main() {
    std::process::exit(if release_middle(40) == 42 { 42 } else { 1 });
}
