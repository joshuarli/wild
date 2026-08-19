//#Object:runtime.c
//#Archive:force_load_member.c
//#LinkArgs:-force_load $OUT_DIR/force_load_member.a
//#ExpectSym:_force_loaded_member
//#DiffIgnore:section.__unwind_info

#include "../common/runtime.h"

// The archive member is deliberately not referenced. `-force_load` must still extract it, which
// makes its externally visible symbol appear in the final Mach-O symbol table.
void main(void) { exit_syscall(42); }
