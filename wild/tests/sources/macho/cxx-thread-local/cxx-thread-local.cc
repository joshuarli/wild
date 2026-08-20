//#Config:default
//#LinkerDriver:clang++
//#LinkArgs:-Wl,-dead_strip
//#DiffIgnore:section.__unwind_info

// Exercise C++'s native Mach-O TLS lowering rather than Rust's runtime wrapper: initialized and
// zero-fill storage must have independent values in the child, then leave the parent unchanged.
#include <pthread.h>

thread_local int initialized = 40;
thread_local unsigned zero_filled;
thread_local int second_initialized = 2;

static void *child_thread(void *) {
  if (initialized != 40 || zero_filled != 0 || second_initialized != 2) {
    return (void *)1;
  }

  initialized += 30;
  zero_filled = 7;
  second_initialized *= 10;
  return initialized == 70 && zero_filled == 7 && second_initialized == 20 ? 0 : (void *)2;
}

int main() {
  ++initialized;
  ++zero_filled;
  ++second_initialized;

  pthread_t child;
  if (pthread_create(&child, nullptr, child_thread, nullptr) != 0) {
    return 3;
  }
  void *result = nullptr;
  if (pthread_join(child, &result) != 0 || result != nullptr) {
    return 4;
  }

  return initialized == 41 && zero_filled == 1 && second_initialized == 3 ? 42 : 5;
}
