//#Object:runtime.c
//#LinkerDriver:clang
//#LinkArgs:-lcompression
//#DiffIgnore:section.__unwind_info

// libcompression's current SDK TBD has no `current-version`. Retain a real imported call so this
// proves both versionless TBD parsing and the load-command identity used by dyld.
#include <compression.h>

#include "../common/runtime.h"

static volatile size_t scratch_size;

void main(void) {
  scratch_size = compression_encode_scratch_buffer_size(COMPRESSION_LZ4);
  exit_syscall(42);
}
