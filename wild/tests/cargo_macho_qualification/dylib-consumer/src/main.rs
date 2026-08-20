fn main() {
    assert_eq!(cargo_macho_dylib_producer::answer(), 42);
    assert_dylib_tls_is_per_thread();
    println!("dylib consumer loaded through its Mach-O rpath");
}

fn assert_dylib_tls_is_per_thread() {
    use cargo_macho_dylib_producer::{dynamic_tls_increment, dynamic_tls_read};

    assert_eq!(dynamic_tls_read(), 40);
    assert_eq!(dynamic_tls_increment(), 41);

    let child = std::thread::spawn(|| {
        assert_eq!(dynamic_tls_read(), 40);
        assert_eq!(dynamic_tls_increment(), 41);
    });
    child.join().expect("Rust dylib TLS thread must complete");

    assert_eq!(dynamic_tls_read(), 41);
}

#[cfg(test)]
mod tests {
    #[test]
    fn dylib_answer_and_tls_are_available_to_the_cargo_test_harness() {
        assert_eq!(cargo_macho_dylib_producer::answer(), 42);
        super::assert_dylib_tls_is_per_thread();
    }
}
