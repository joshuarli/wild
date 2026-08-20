//#LinkerDriver:clang++

thread_local int cxx_dylib_initialized = 40;
thread_local unsigned cxx_dylib_zero_filled;

extern "C" int cxx_dylib_increment() { return ++cxx_dylib_initialized; }

extern "C" unsigned cxx_dylib_set_zero(unsigned value) {
  cxx_dylib_zero_filled = value;
  return cxx_dylib_zero_filled;
}
