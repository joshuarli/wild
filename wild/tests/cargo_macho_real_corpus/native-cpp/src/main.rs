unsafe extern "C" {
    fn cargo_macho_corpus_native_cpp_answer(value: i32) -> i32;
}

fn answer() -> i32 {
    unsafe { cargo_macho_corpus_native_cpp_answer(41) }
}

fn main() {
    assert_eq!(answer(), 42);
}

#[cfg(test)]
mod tests {
    #[test]
    fn calls_native_cpp() {
        assert_eq!(super::answer(), 42);
    }
}
