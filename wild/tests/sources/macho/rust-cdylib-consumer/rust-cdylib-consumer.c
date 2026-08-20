//#LinkerDriver:clang
//#Shared:rust-cdylib-producer.rs
//#DiffIgnore:section.__unwind_info

// The Rust producer reaches Wild through its saved rustc link replay. Rustc supplies
// -exported_symbols_list from a temporary path; the C executable proves the replayed cdylib both
// retained that list and exported the requested C ABI symbol.
int rust_cdylib_answer(void);

int main(void) { return rust_cdylib_answer() == 42 ? 42 : 1; }
