//#Object:runtime.c
//#Object:cstring-merging-a.c
//#Object:cstring-merging-b.c
//#LinkerDriver:clang
//#LinkArgs:-Wl,-dead_strip
//#DiffIgnore:section.__unwind_info

// Darwin marks these literals as `__TEXT,__cstring`. The final linker must merge equal literals
// across object files and redirect both relocations to the one output address; using one input
// section's offset for both would make this pointer comparison fail.
#include "../common/runtime.h"

const char *cstring_merging_a(void);
const char *cstring_merging_b(void);

void main(void) {
  const char *a = cstring_merging_a();
  const char *b = cstring_merging_b();
  exit_syscall(a == b && a[0] == 'w' ? 42 : 1);
}
