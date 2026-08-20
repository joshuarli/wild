//#Arch:aarch64
//#RustcToolchain:nightly-2026-07-24
//#ExpectMachOLoadCommand:dylib:path=/System/Library/Frameworks/Security.framework/Versions/A/Security,current=61901.120.67,compatibility=1.0.0

// This is the Rust-side SDK framework contract. `#[link(kind = "framework")]` must reach
// rustc's normal Darwin linker path, resolve the SDK Security TAPI export through Wild, retain
// the two-level ordinal, and let dyld call the actual framework function at runtime.
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecRandomCopyBytes(random: *const core::ffi::c_void, count: usize, bytes: *mut u8) -> i32;
}

fn main() {
    let mut byte = 0u8;
    let status = unsafe { SecRandomCopyBytes(core::ptr::null(), 1, &mut byte) };
    std::process::exit(if status == 0 { 42 } else { 1 });
}
