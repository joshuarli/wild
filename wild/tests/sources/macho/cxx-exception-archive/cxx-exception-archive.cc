//#Arch:aarch64
//#LinkerDriver:clang++
//#CompArgs:-g -std=c++14
//#LinkArgs:-Wl,-dead_strip
//#Archive:cxx-exception-archive-helper.cc
//#ExpectSection:__unwind_info
//#ExpectDsymutilSymbol:_wild_cxx_exception_archive_throw
//#NoDsymutilSymbol:_wild_cxx_exception_archive_unused
//#ExpectDsymutilLldb:function=wild_cxx_exception_archive_throw,source=cxx-exception-archive-helper.cc,line=3
//#NoSection:__debug_info
//#DiffIgnore:section.__unwind_info

extern "C" void wild_cxx_exception_archive_throw();

int main() {
  try {
    wild_cxx_exception_archive_throw();
  } catch (int answer) {
    return answer == 42 ? 42 : 1;
  }

  return 1;
}
