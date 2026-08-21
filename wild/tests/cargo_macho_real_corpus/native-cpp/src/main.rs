unsafe extern "C" {
    fn cargo_macho_corpus_native_cpp_answer(value: i32) -> i32;
}

// The benchmark changes this fixed-width input while retaining the native archive. The volatile
// read keeps it as a live direct-object data patch rather than allowing release codegen to fold
// the value into `main`.
static CACHE_MARKER: i32 = 0;

#[inline(never)]
fn cache_marker() -> i32 {
    unsafe { std::ptr::read_volatile(&CACHE_MARKER) }
}

fn answer() -> i32 {
    unsafe { cargo_macho_corpus_native_cpp_answer(41) }
}

fn main() {
    let marker = cache_marker();
    assert_eq!(answer() + marker, 42 + marker);
}

#[cfg(test)]
mod tests {
    #[test]
    fn calls_native_cpp() {
        assert_eq!(super::answer(), 42);
    }

    #[test]
    fn cache_marker_is_live_without_changing_the_native_result() {
        let marker = super::cache_marker();
        assert_eq!(super::answer() + marker, 42 + marker);
    }
}
