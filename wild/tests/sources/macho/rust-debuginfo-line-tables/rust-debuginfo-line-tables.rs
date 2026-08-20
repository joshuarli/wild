//#Arch:aarch64
//#RustcToolchain:nightly-2026-07-24
//#CompArgs:-C debuginfo=1 -C link-arg=-dead_strip
//#ExpectDsymutilSymbol:_wild_rust_debuginfo_line_tables_add
//#NoDsymutilSymbol:_wild_rust_debuginfo_line_tables_unused
//#ExpectDsymutilLldb:function=wild_rust_debuginfo_line_tables_add,source=rust-debuginfo-line-tables.rs,line=14
//#NoSection:__debug_info

// Rust's line-tables-only debug level still needs the same loose-object debug map contract:
// dsymutil reconstructs source locations from N_OSO/N_FUN records after `-dead_strip`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn wild_rust_debuginfo_line_tables_add(value: i32) -> i32 {
    value + 1
}

#[inline(never)]
fn wild_rust_debuginfo_line_tables_unused() -> i32 {
    7
}

fn main() {
    std::process::exit(if wild_rust_debuginfo_line_tables_add(41) == 42 {
        42
    } else {
        1
    });
}
