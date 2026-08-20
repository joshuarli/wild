// Keep the stress source compact while making every dynamic import independent. LLVM's Darwin
// assembler expands `\+` once per repetition, producing 2300 exported data definitions.
.section __DATA,__data
.p2align 3
.altmacro
.rept 2300
.globl _chained_fixup_data_\+
_chained_fixup_data_\+:
    .quad 1
.endr
