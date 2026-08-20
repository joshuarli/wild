//#LinkerDriver:clang
//#Shared:chained-fixups-tlvp-provider.s

// Two imported TLS descriptors require two chained binds. The first slot at offset zero did not
// expose a byte-vs-scaled LDR page-offset bug; the second slot must be addressed at +8 and loaded
// through its descriptor bootstrap before this executable can return 42.
.section __TEXT,__text,regular,pure_instructions
.globl _main
.p2align 2
_main:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x19, [sp, #16]

    adrp x0, _chained_tlvp_first@TLVPPAGE
    ldr x0, [x0, _chained_tlvp_first@TLVPPAGEOFF]
    ldr x8, [x0]
    blr x8
    ldr w19, [x0]

    adrp x0, _chained_tlvp_second@TLVPPAGE
    ldr x0, [x0, _chained_tlvp_second@TLVPPAGEOFF]
    ldr x8, [x0]
    blr x8
    ldr w0, [x0]
    add w0, w19, w0

    mov w3, #42
    mov w4, #1
    cmp w0, #42
    csel w0, w3, w4, eq
    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
