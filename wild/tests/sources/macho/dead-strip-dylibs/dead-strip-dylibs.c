//#Object:runtime.c
//#LinkerDriver:clang
//#LinkArgs:-Wl,-dead_strip_dylibs
//#LinkSoArgs:-Wl,-install_name,@rpath/libwild-dead-strip-unused.dylib
//#Shared:dead-strip-dylibs-unused.c
//#DoesNotContain:@rpath/libwild-dead-strip-unused.dylib
//#DiffIgnore:section.__unwind_info

#include "../common/runtime.h"

// ld64 must omit a dylib with no surviving imports under `-dead_strip_dylibs`; the install name
// would otherwise become a useless load command and force dyld to locate the library at launch.
void main(void) { exit_syscall(42); }
