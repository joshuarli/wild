// LLVM's Darwin assembler expands `\+` once per repetition. Each exported word makes the
// consumer allocate a distinct chained bind rather than coalescing a shared GOT entry.
.section __DATA,__data
.p2align 3
.altmacro
.rept 10000
.globl _chained_fixup_stress_data_\+
_chained_fixup_stress_data_\+:
    .quad 1
.endr
