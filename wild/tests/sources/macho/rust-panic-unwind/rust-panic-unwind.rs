//#CompArgs:-Cpanic=unwind -Clink-arg=-dead_strip
//#ExpectSection:__eh_frame
//#ExpectSection:__unwind_info
//#DiffIgnore:section.__eh_frame
//#DiffIgnore:section.__unwind_info

// This requires the linker to preserve DWARF-mode compact-unwind rows, rewrite their FDE
// offsets after serializing the final `__TEXT,__eh_frame`, and initialize the CIE personality
// pointer's local GOT cell. `-dead_strip` makes the FDE selection use atom liveness as well.
#[inline(never)]
fn leaf() {
    panic!("expected panic");
}

#[inline(never)]
fn intermediate() {
    leaf();
}

fn main() {
    if std::panic::catch_unwind(intermediate).is_ok() {
        std::process::exit(101);
    }

    std::process::exit(42);
}
