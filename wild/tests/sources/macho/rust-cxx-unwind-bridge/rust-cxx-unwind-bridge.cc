extern "C" void wild_rust_cxx_unwind_bridge_cleaned();
extern "C" void wild_rust_cxx_unwind_bridge_panic();

struct CppCleanup {
  ~CppCleanup() { wild_rust_cxx_unwind_bridge_cleaned(); }
};

extern "C" void wild_rust_cxx_unwind_bridge_call() {
  CppCleanup cleanup;
  wild_rust_cxx_unwind_bridge_panic();
}
