//#Object:padding-1.s
//#Object:padding-2.s
//#Object:target.s
//#Object:runtime.c

// `BL` shares BRANCH26's range but additionally needs the island to preserve x30 so the final
// target can return to this caller. The target is deliberately beyond the direct +/-128 MiB
// range and the caller only exits after the return value has crossed the island.
.globl _main
.p2align 2
_main:
    bl _target
    b _exit_syscall
