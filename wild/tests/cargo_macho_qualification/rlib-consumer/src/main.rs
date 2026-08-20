fn main() {
    assert_eq!(cargo_macho_rlib_producer::answer(), 42);
    println!("rlib consumer linked through Wild");
}
