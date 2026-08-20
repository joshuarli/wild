//#Arch:aarch64
//#RustcToolchain:nightly-2026-07-24
//#CompArgs:-g -Clink-arg=-dead_strip
//#ExpectDsymutilSymbol:_wild_rust_debug_dwarf_add
//#NoDsymutilSymbol:_wild_rust_debug_dwarf_unused
//#ExpectDsymutilLldb:function=wild_rust_debug_dwarf_add,source=rust-debug-dwarf.rs,line=14
//#NoSection:__debug_info

// The normal ARM64 Rust executable keeps ordinary DWARF out of the final binary. The dSYM must
// instead be reconstructed from the dated nightly's loose object via N_OSO/N_FUN debug-map rows.
#[no_mangle]
#[inline(never)]
pub extern "C" fn wild_rust_debug_dwarf_add(value: i32) -> i32 {
    value + 1
}

#[inline(never)]
fn wild_rust_debug_dwarf_unused() -> i32 {
    7
}

fn main() {
    std::process::exit(if wild_rust_debug_dwarf_add(41) == 42 {
        42
    } else {
        1
    });
}
