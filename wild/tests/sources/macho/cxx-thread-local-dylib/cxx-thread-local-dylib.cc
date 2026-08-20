//#Config:default
//#LinkerDriver:clang++
//#LinkArgs:-Wl,-dead_strip
//#DiffIgnore:section.__unwind_info
//#Shared:cxx-thread-local-dylib-producer.cc

// Imported C++ TLS must use a dyld-bound descriptor rather than an executable-local address.
// Exercise both initialized and zero-fill variables directly and through the dylib's functions;
// the second thread must start from its own initializer values.
#include <pthread.h>

extern thread_local int cxx_dylib_initialized;
extern thread_local unsigned cxx_dylib_zero_filled;
extern "C" int cxx_dylib_increment();
extern "C" unsigned cxx_dylib_set_zero(unsigned value);

static void *child_thread(void *) {
  if (cxx_dylib_initialized != 40 || cxx_dylib_zero_filled != 0) {
    return reinterpret_cast<void *>(1);
  }
  if (cxx_dylib_increment() != 41 || cxx_dylib_initialized != 41) {
    return reinterpret_cast<void *>(2);
  }
  return cxx_dylib_set_zero(7) == 7 && cxx_dylib_zero_filled == 7
             ? nullptr
             : reinterpret_cast<void *>(3);
}

int main() {
  if (cxx_dylib_initialized != 40 || cxx_dylib_zero_filled != 0) {
    return 1;
  }
  if (cxx_dylib_increment() != 41 || cxx_dylib_set_zero(1) != 1) {
    return 2;
  }

  pthread_t child;
  if (pthread_create(&child, nullptr, child_thread, nullptr) != 0) {
    return 3;
  }
  void *result = nullptr;
  if (pthread_join(child, &result) != 0 || result != nullptr) {
    return 4;
  }

  return cxx_dylib_initialized == 41 && cxx_dylib_zero_filled == 1 ? 42 : 5;
}
