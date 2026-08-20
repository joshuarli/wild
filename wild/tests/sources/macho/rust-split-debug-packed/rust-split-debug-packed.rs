//#Arch:aarch64
//#RustcToolchain:nightly-2026-07-24
//#CompArgs:-g -C split-debuginfo=packed -C link-arg=-dead_strip
//#ExpectDsymutilSymbol:_wild_rust_split_debug_packed_add
//#NoDsymutilSymbol:_wild_rust_split_debug_packed_unused
//#ExpectDsymutilLldb:function=wild_rust_split_debug_packed_add,source=rust-split-debug-packed.rs,line=15
//#NoSection:__debug_info

// Exercise the other dated-nightly Darwin split-debug spelling. Like `unpacked`, the final image
// must retain only a valid dSYM debug map; dsymutil owns the DWARF rewrite from rustc's loose
// object and its packed companion data.
#[no_mangle]
#[inline(never)]
pub extern "C" fn wild_rust_split_debug_packed_add(value: i32) -> i32 {
    value + 1
}

#[inline(never)]
fn wild_rust_split_debug_packed_unused() -> i32 {
    7
}

fn main() {
    std::process::exit(if wild_rust_split_debug_packed_add(41) == 42 {
        42
    } else {
        1
    });
}
