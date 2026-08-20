//#LinkerDriver:clang
//#Shared:chained-fixups-10000-provider.s

// Five 16 KiB pages are required for 10,000 eight-byte GOT slots. Every import has a distinct
// ordinal and address, then contributes one to the result; success requires dyld to start and
// terminate chains correctly across all pages rather than validating only the first page.
.section __TEXT,__text,regular,pure_instructions
.globl _main
.p2align 2
_main:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x19, [sp, #16]
    mov w19, #0

.altmacro
.rept 10000
    adrp x1, _chained_fixup_stress_data_\+@GOTPAGE
    ldr x1, [x1, _chained_fixup_stress_data_\+@GOTPAGEOFF]
    ldr w2, [x1]
    add w19, w19, w2
.endr

    mov w3, #10000
    mov w4, #1
    cmp w19, w3
    // The return status is constrained to 42 while the preceding comparison proves every binding
    // contributed. MOV does not change the comparison flags used by CSEL.
    mov w3, #42
    csel w0, w3, w4, eq
    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
