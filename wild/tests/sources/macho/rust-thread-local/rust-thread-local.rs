// A Rust `thread_local!` value must have independent storage for each thread while still
// preserving the caller's value after a child thread exits. This exercises the Mach-O TLV
// sections and the runtime bootstrap used by a normal Rust executable.
thread_local! {
    static VALUE: std::cell::Cell<u32> = const { std::cell::Cell::new(40) };
}

fn main() {
    VALUE.with(|value| value.set(value.get() + 1));

    let child = std::thread::spawn(|| {
        VALUE.with(|value| {
            value.set(value.get() + 30);
            value.get()
        })
    });

    let parent = VALUE.with(std::cell::Cell::get);
    let child = child.join().unwrap();
    let parent_after_join = VALUE.with(std::cell::Cell::get);

    std::process::exit(if parent == 41 && child == 70 && parent_after_join == 41 {
        42
    } else {
        1
    });
}
