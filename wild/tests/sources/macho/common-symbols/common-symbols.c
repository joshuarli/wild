//#Object:runtime.c
//#Object:common-symbols-other.c
//#CompArgs:-fcommon
//#ExpectSym:_wild_common_shared section="__common",segment="__DATA",alignment=8
//#ExpectSym:_wild_common_other section="__common",segment="__DATA",alignment=4
//#DiffIgnore:section.__unwind_info

//#Config:dead-strip:default
//#LinkArgs:-dead_strip
//#NoDynSym:_wild_common_shared
//#NoDynSym:_wild_common_other

// Darwin represents tentative C definitions as external N_UNDF records with a nonzero n_value,
// rather than as section definitions. The second object makes the selected definition larger;
// the executable must allocate it once in __DATA,__common and use that address from both files.
#include "../common/runtime.h"

int wild_common_shared;
int wild_common_other;

void main(void) {
  wild_common_shared = 40;
  wild_common_other = 2;
  exit_syscall(wild_common_shared + wild_common_other);
}
