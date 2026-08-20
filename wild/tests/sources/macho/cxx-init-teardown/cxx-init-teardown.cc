//#Object:runtime.c
//#LinkerDriver:clang++
//#DiffIgnore:section.__unwind_info

// Clang registers this object's destructor with __cxa_atexit using ___dso_handle. The constructor
// must run before main, main's atexit callback must run before the global destructor, and the
// destructor uses the freestanding exit shim so the executable's status observes that ordering.
extern "C" int atexit(void (*)(void));
extern "C" void exit_syscall(int);

static int state;

struct Teardown {
  Teardown() { state = 1; }
  ~Teardown() { exit_syscall(state == 2 ? 42 : 1); }
};

static Teardown teardown;

static void after_main(void) { state = state == 1 ? 2 : 3; }

int main(void) { return state == 1 ? atexit(after_main) : 1; }
