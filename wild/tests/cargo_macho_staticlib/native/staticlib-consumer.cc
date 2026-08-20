extern "C" int wild_staticlib_add_host(int value);
extern "C" unsigned wild_staticlib_factorial(unsigned value);
extern "C" void wild_staticlib_call_thrower();

extern "C" int wild_staticlib_host_value() { return 19; }

struct CrossRustBoundary {};

extern "C" void wild_staticlib_thrower() { throw CrossRustBoundary{}; }

int main() {
  // The exported Rust functions and the callback in the other direction must both cross the
  // static-library boundary correctly. Returning 42 lets the integration harness use the same
  // observable convention as the assembly fixtures.
  if (wild_staticlib_add_host(23) != 42 || wild_staticlib_factorial(5) != 120) {
    return 1;
  }

  try {
    wild_staticlib_call_thrower();
    return 2;
  } catch (const CrossRustBoundary &) {
    return 42;
  } catch (...) {
    return 3;
  }
}
