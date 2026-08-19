//#LinkerDriver:clang
//#CompArgs:-g
//#LinkArgs:-Wl,-dead_strip
//#ExpectDsymutilSymbol:_wild_debug_dwarf_add
//#ExpectDsymutilSymbol:_main
//#NoDsymutilSymbol:_wild_debug_dwarf_unused
//#NoSection:__debug_info

// The final executable deliberately has no __DWARF segment. `dsymutil` must reconstruct the
// dSYM from this retained input object through N_OSO/N_FUN debug-map records.
__attribute__((noinline)) int wild_debug_dwarf_add(int value) {
  return value + 1;
}

static __attribute__((noinline)) int wild_debug_dwarf_unused(void) {
  return 7;
}

int main(void) {
  return wild_debug_dwarf_add(41);
}
