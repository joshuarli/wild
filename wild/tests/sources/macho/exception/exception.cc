//#LinkerDriver:clang++
//#LinkArgs:-Wl,-dead_strip
//#ExpectSection:__unwind_info
//#ExpectSectionBytes:__unwind_info=0x01000000 0..4
//#DiffIgnore:section.__unwind_info
//#DiffIgnore:section.__gcc_except_tab

#include <iostream>

__attribute__((noinline)) void throw_answer() { throw 42; }

__attribute__((noinline)) void cross_frame() { throw_answer(); }

int main() {
  try {
    cross_frame();
  } catch (int answer) {
    std::cout << answer << '\n';
    return answer;
  }

  return 1;
}
