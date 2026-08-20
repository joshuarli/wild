//#Object:runtime.c
//#LinkerDriver:clang
//#LinkArgs:-framework Accelerate
//#DiffIgnore:section.__unwind_info

// Accelerate reexports vecLib, and vecLib reexports libBLAS. `cblas_sdot` is therefore a leaf of
// a nested TBD reexport graph rather than an export listed by Accelerate's root document.
#include <Accelerate/Accelerate.h>

#include "../common/runtime.h"

void main(void) {
  const float a[] = {2.0f};
  const float b[] = {3.0f};
  exit_syscall(cblas_sdot(1, a, 1, b, 1) == 6.0f ? 42 : 1);
}
