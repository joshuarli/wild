//#Object:runtime.c
//#DiffIgnore:section.__unwind_info

// Mach-O arm64 keeps PAGE/PAGEOFF addends in separate ARM64_RELOC_ADDEND records. The source
// location is deliberately not the data label itself: both instructions must fold the explicit
// +4 addend before resolving `_result_base`.
.globl _main
.p2align 2
_main:
    adrp x0, _result_base@PAGE + 4
    ldr w0, [x0, _result_base@PAGEOFF + 4]
    b _exit_syscall

.section __DATA,__data
.p2align 2
_result_base:
    .long 0
    .long 42
