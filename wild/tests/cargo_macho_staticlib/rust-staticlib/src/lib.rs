// The C++ executable supplies this callback. Keeping an incoming native call in the Rust
// archive makes the final native link resolve symbols in both directions.
unsafe extern "C" {
    fn wild_staticlib_host_value() -> i32;
}

// A C++ caller throws through this export and catches at its original native frame. `C-unwind`
// makes that cross-language unwind boundary part of Rust's ABI contract instead of relying on an
// ordinary `extern "C"` call, which must not propagate an exception.
unsafe extern "C-unwind" {
    fn wild_staticlib_thrower();
}

#[unsafe(no_mangle)]
pub extern "C" fn wild_staticlib_add_host(value: i32) -> i32 {
    value + unsafe { wild_staticlib_host_value() }
}

#[unsafe(no_mangle)]
pub extern "C" fn wild_staticlib_factorial(value: u32) -> u32 {
    let mut result: u32 = 1;
    let mut factor = 2;
    while factor <= value {
        result = result.wrapping_mul(factor);
        factor += 1;
    }
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn wild_staticlib_call_thrower() {
    unsafe { wild_staticlib_thrower() };
}
