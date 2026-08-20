//#Arch:aarch64
//#LinkerDriver:clang++
//#CompArgs:-g -std=c++14
//#LinkArgs:-Wl,-dead_strip
//#ExpectDsymutilSymbol:_wild_cxx_debug_dwarf_add
//#NoDsymutilSymbol:_wild_cxx_debug_dwarf_unused
//#ExpectDsymutilLldb:function=wild_cxx_debug_dwarf_add,source=cxx-debug-dwarf.cc,line=13
//#NoSection:__debug_info

// The C++ control is intentionally a loose object. Its C ABI helper makes the map's live/dead
// atom contract independent of C++ name mangling while the CU itself records DW_LANG_C_plus_plus.
extern "C" __attribute__((noinline)) int wild_cxx_debug_dwarf_add(int value) {
  return value + 1;
}

static __attribute__((noinline)) int wild_cxx_debug_dwarf_unused(void) {
  return 7;
}

int main() {
  return wild_cxx_debug_dwarf_add(41);
}
