//#Object:runtime.c
//#LinkerDriver:clang
//#LinkArgs:-liconv
//#ExpectMachOLoadCommand:dylib:path=/usr/lib/libiconv.2.dylib,current=7.0.0,compatibility=7.0.0
//#DoesNotContain:/usr/lib/libcharset.1.dylib
//#DiffIgnore:section.__unwind_info

#include "../common/runtime.h"

// libiconv's SDK stub reexports libcharset through a *separate* libcharset.1.tbd file. The
// consumer must retain only libiconv's install name: dyld follows that reexport itself.
void main(void) { exit_syscall(42); }
