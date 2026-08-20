//#LinkerDriver:clang
//#Shared:chained-fixups-multipage-provider.s

// A 16 KiB chained-fixup page holds 2048 eight-byte GOT slots. This generated source reads all
// 2300 imported data slots and accepts only their complete sum, so runtime success requires dyld
// to bind both pages rather than merely parse the chained-fixup blob.
.section __TEXT,__text,regular,pure_instructions
.globl _main
.p2align 2
_main:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x19, [sp, #16]
    mov w19, #0

.altmacro
.rept 2300
    adrp x1, _chained_fixup_data_\+@GOTPAGE
    ldr x1, [x1, _chained_fixup_data_\+@GOTPAGEOFF]
    ldr w2, [x1]
    add w19, w19, w2
.endr

    mov w3, #42
    mov w4, #1
    cmp w19, #2300
    csel w0, w3, w4, eq
    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
