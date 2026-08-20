use cargo_macho_macro_producer::answer;

fn main() {
    assert_eq!(answer!(), 42);
    println!("proc macro expanded and ran");
}
