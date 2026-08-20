fn main() {
    assert_eq!(cargo_macho_dylib_producer::answer(), 42);
    println!("dylib consumer loaded through its Mach-O rpath");
}
