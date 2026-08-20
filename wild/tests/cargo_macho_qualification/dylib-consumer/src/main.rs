fn main() {
    assert_eq!(cargo_macho_dylib_producer::answer(), 42);
    println!("dylib consumer loaded through its Mach-O rpath");
}

#[cfg(test)]
mod tests {
    #[test]
    fn dylib_answer_is_available_to_the_cargo_test_harness() {
        assert_eq!(cargo_macho_dylib_producer::answer(), 42);
    }
}
