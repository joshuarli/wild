.subsections_via_symbols

.section __TEXT,__cstring,cstring_literals
Lwild_cstring_identity_prefix:
    .asciz "shared cstring prefix"
Lwild_cstring_identity_slot:
    .asciz "A local cstring slot"

.section __TEXT,__text,regular,pure_instructions
.p2align 2
.globl _wild_cstring_identity_a
_wild_cstring_identity_a:
    adrp x0, Lwild_cstring_identity_slot@PAGE
    add x0, x0, Lwild_cstring_identity_slot@PAGEOFF
    ret
