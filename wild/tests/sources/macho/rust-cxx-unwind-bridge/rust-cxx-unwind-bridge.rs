//#Arch:aarch64
//#RustcToolchain:nightly-2026-07-24
//#Archive:rust-cxx-unwind-bridge.cc
//#ExpectSection:__eh_frame
//#ExpectSection:__unwind_info
//#DiffIgnore:section.__eh_frame
//#DiffIgnore:section.__unwind_info

// The panic leaves Rust, crosses a C++ frame with a live destructor, and returns to Rust's
// catch_unwind. The atomic is only incremented by that C++ destructor, so this covers cleanup
// as well as transport through the mixed stack.
use std::sync::atomic::{AtomicUsize, Ordering};

static CXX_CLEANUP_COUNT: AtomicUsize = AtomicUsize::new(0);

#[link(name = "c++")]
unsafe extern "C-unwind" {
    fn wild_rust_cxx_unwind_bridge_call();
}

#[no_mangle]
pub extern "C" fn wild_rust_cxx_unwind_bridge_cleaned() {
    CXX_CLEANUP_COUNT.fetch_add(1, Ordering::SeqCst);
}

#[no_mangle]
pub extern "C-unwind" fn wild_rust_cxx_unwind_bridge_panic() {
    panic!("unwind through C++ cleanup");
}

fn main() {
    let caught = std::panic::catch_unwind(|| unsafe {
        wild_rust_cxx_unwind_bridge_call();
    })
    .is_err();
    std::process::exit(if caught && CXX_CLEANUP_COUNT.load(Ordering::SeqCst) == 1 {
        42
    } else {
        1
    });
}
