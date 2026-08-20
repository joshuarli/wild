//#AbstractConfig:base
//#LinkerDriver:clang
//#CompArgs:-g
//#LinkArgs:-Wl,-dead_strip
//#DiffIgnore:section.__unwind_info

//#Config:strip-debug:base
//#LinkArgs:-Wl,-S
//#NoDsymutilSymbol:_wild_strip_symbols_visible

//#Config:strip-all:base
//#LinkArgs:-Wl,-s

// `-S` removes the linker-owned debug map. `-s` exercises Wild's all-symbol writer path; both
// variants must retain executable code and exit normally.
__attribute__((noinline)) int wild_strip_symbols_visible(int value) { return value + 1; }

int main(void) { return wild_strip_symbols_visible(41); }
