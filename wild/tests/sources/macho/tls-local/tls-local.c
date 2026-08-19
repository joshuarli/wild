//#Config:default
//#LinkerDriver:clang
//#DiffIgnore:section.__unwind_info
//#Object:runtime.c

// A Mach-O TLVP relocation targets this descriptor, not an ELF-style TLS offset.
// The code below exercises the complete local descriptor path: TLVPPAGE/TLVPPAGEOFF
// resolve the descriptor address, and its bootstrap function returns this thread's data.
#include "../common/runtime.h"

static _Thread_local int counter = 40;

void main(void) {
  exit_syscall(++counter == 41 ? 42 : 1);
}
