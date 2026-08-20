use std::cell::Cell;

// This state belongs to the dynamically loaded Rust dylib. Keeping the qualification here
// exercises a thread-variable descriptor imported across the dylib boundary rather than only a
// thread-local in the executable that happens to call a dylib function.
thread_local! {
    static DYNAMIC_DYLIB_TLS: Cell<i32> = const { Cell::new(40) };
}

pub fn answer() -> i32 {
    42
}

pub fn dynamic_tls_read() -> i32 {
    DYNAMIC_DYLIB_TLS.with(Cell::get)
}

pub fn dynamic_tls_increment() -> i32 {
    DYNAMIC_DYLIB_TLS.with(|value| {
        let next = value.get() + 1;
        value.set(next);
        next
    })
}
