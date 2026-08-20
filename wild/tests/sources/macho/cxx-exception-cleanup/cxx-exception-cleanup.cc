//#LinkerDriver:clang++
//#LinkArgs:-Wl,-dead_strip
//#ExpectSection:__unwind_info
//#DiffIgnore:section.__unwind_info
//#DiffIgnore:section.__gcc_except_tab

// A successful catch alone does not prove that the landing pad used the LSDA correctly. This
// destructor runs only while unwinding the throwing frame, so the final 42 is a runtime check of
// C++ cleanup semantics in addition to the existing compact-unwind structural assertion.
struct Cleanup {
  explicit Cleanup(int &state) : state(state) {}
  ~Cleanup() { state += 42; }

  int &state;
};

int main() {
  int state = 0;
  try {
    Cleanup cleanup(state);
    throw 7;
  } catch (int value) {
    return value == 7 && state == 42 ? 42 : 1;
  }
}
