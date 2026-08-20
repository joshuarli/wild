//#Arch:aarch64
//#RustcToolchain:nightly-2026-07-24
//#CompArgs:-g -C split-debuginfo=unpacked -C link-arg=-dead_strip
//#ExpectDsymutilSymbol:_wild_rust_split_debug_dwarf_add
//#NoDsymutilSymbol:_wild_rust_split_debug_dwarf_unused
//#ExpectDsymutilLldb:function=wild_rust_split_debug_dwarf_add,source=rust-split-debug-dwarf.rs,line=15
//#NoSection:__debug_info

// Exercise rustc's normal Darwin split-debug invocation through the same dSYM map path. This is
// intentionally a small standalone executable so any failure identifies the linker/debug-map
// contract rather than archive or dylib debug-info behavior.
#[no_mangle]
#[inline(never)]
pub extern "C" fn wild_rust_split_debug_dwarf_add(value: i32) -> i32 {
    value + 1
}

#[inline(never)]
fn wild_rust_split_debug_dwarf_unused() -> i32 {
    7
}

fn main() {
    std::process::exit(if wild_rust_split_debug_dwarf_add(41) == 42 {
        42
    } else {
        1
    });
}
