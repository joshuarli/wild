//#Object:rust-native-ffi.c

// A normal Rust executable must be able to call a separately compiled Mach-O C object using the
// platform C ABI. This keeps the phase-20 symbol work grounded in the Rust/native boundary rather
// than only freestanding C fixtures.
unsafe extern "C" {
    fn wild_native_abi_add(left: i32, right: i32) -> i32;
}

fn main() {
    let result = unsafe { wild_native_abi_add(19, 23) };
    std::process::exit(if result == 42 { 42 } else { 1 });
}
