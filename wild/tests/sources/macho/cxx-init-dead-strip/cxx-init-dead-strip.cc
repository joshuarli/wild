//#Arch:aarch64
//#LinkerDriver:clang++
//#LinkArgs:-Wl,-dylib,-dead_strip,-dylib_install_name,@rpath/libcxx-init-dead-strip.dylib
//#RunDynSym:cxx_init_dead_strip
//#NoSym:_cxx_init_dead_strip_unused
//#DiffIgnore:section.__unwind_info

// A C++ translation unit can contribute no directly referenced code except its
// `__mod_init_func` entry. Under `-dead_strip`, the initializer section must
// keep its relocation target alive even though the exported query is otherwise
// independent of the constructor atom.
static int initialized_state;

struct InitOnly {
  InitOnly() { initialized_state = 42; }
};

static InitOnly init_only;

extern "C" int cxx_init_dead_strip(void) { return initialized_state; }

extern "C" __attribute__((noinline, visibility("hidden"))) int
cxx_init_dead_strip_unused(void) {
  return 7;
}
