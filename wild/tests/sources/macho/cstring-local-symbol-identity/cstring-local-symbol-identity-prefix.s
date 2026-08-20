.subsections_via_symbols

// This regular, 16-byte-aligned section has the same output identity as the cstring-literal
// sections below but occupies a preceding alignment part. The merger must still resolve local
// cstring references from the base at which the section-wide writer emits its buckets.
.section __TEXT,__cstring,regular
.p2align 4
Lwild_cstring_identity_prefix:
    .asciz "Prefix before merged cstrings"

.section __TEXT,__text,regular,pure_instructions
.p2align 2
.globl _wild_cstring_identity_prefix
_wild_cstring_identity_prefix:
    adrp x0, Lwild_cstring_identity_prefix@PAGE
    add x0, x0, Lwild_cstring_identity_prefix@PAGEOFF
    ret
