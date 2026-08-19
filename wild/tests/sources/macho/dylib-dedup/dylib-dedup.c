//#Object:runtime.c
//#LinkerDriver:clang
//#LinkArgs:-lSystem -lc -lm
//#DiffIgnore:section.__unwind_info

// `libSystem`, `libc`, and `libm` are distinct SDK stubs with the same install name. The output
// must have a single load command for that install name, while every import retains its ordinal.
#include "../common/runtime.h"

void main(void) { exit_syscall(42); }
