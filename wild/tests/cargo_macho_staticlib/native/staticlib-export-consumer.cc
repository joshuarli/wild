extern "C" int wild_staticlib_add_host(int value);
extern "C" unsigned wild_staticlib_factorial(unsigned value);

extern "C" int wild_staticlib_host_value() { return 19; }

// `wild_staticlib_call_thrower` shares the Rust object that exports the functions under test.
// Supply its unused native callback so the native linker can consume the static archive without
// making the export-only control depend on the C++ exception path.
extern "C" void wild_staticlib_thrower() {}

int main() {
  return wild_staticlib_add_host(23) == 42 && wild_staticlib_factorial(5) == 120 ? 0 : 1;
}
