//#CompArgs:--test -Cpanic=unwind -Cdebuginfo=2 -Clink-arg=-dead_strip
//#ExpectedExit:0

//#Config:stable:default
//#RustcToolchain:stable

// A Rust test harness catches failures while it tears down its test-description vector. This
// exercises the cleanup landing-pad path that a normal `fn main` does not reach.
#[test]
fn completes_before_harness_cleanup() {
    assert!(std::panic::catch_unwind(|| panic!("expected test-harness unwind")).is_err());
}
