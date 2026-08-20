//#Object:external.s
//#Object:runtime.c
//#LinkerDriver:clang
//#LinkArgs:-Wl,-dead_strip
//#NoSym:_wild_subtractor_dead_atom

// ARM64 Mach-O represents `minuend - subtrahend + addend` as adjacent relocation records at
// the same 64-bit data word: ARM64_RELOC_SUBTRACTOR names the subtrahend and the following
// ARM64_RELOC_UNSIGNED names the minuend. The in-place word is the signed addend. This fixture
// deliberately covers both targets in this object and a minuend defined by another object.
//
// `-dead_strip` makes the pair a graph edge to *both* input atoms. `_main` observes the final
// values, while the unreferenced global proves that the loader does not accidentally retain its
// neighbouring data atom.
.subsections_via_symbols

.section __TEXT,__text,regular,pure_instructions
.p2align 2
.globl _main
_main:
    adrp x8, _wild_subtractor_local_value@PAGE
    ldr x0, [x8, _wild_subtractor_local_value@PAGEOFF]
    adrp x8, _wild_subtractor_local_minuend@PAGE
    add x1, x8, _wild_subtractor_local_minuend@PAGEOFF
    adrp x8, _wild_subtractor_local_subtrahend@PAGE
    add x2, x8, _wild_subtractor_local_subtrahend@PAGEOFF
    sub x1, x1, x2
    add x1, x1, #17
    cmp x0, x1
    b.ne Lfailure

    adrp x8, _wild_subtractor_external_value@PAGE
    ldr x0, [x8, _wild_subtractor_external_value@PAGEOFF]
    adrp x8, _wild_subtractor_external_minuend@PAGE
    add x1, x8, _wild_subtractor_external_minuend@PAGEOFF
    adrp x8, _wild_subtractor_external_subtrahend@PAGE
    add x2, x8, _wild_subtractor_external_subtrahend@PAGEOFF
    sub x1, x1, x2
    sub x1, x1, #9
    cmp x0, x1
    b.ne Lfailure

    // This third pair evaluates to 0x100000000, an in-image-looking integer. Apple ld leaves
    // that arithmetic result raw rather than turning the unsigned companion into a dyld rebase;
    // this catches an output-side pointer classification shortcut.
    adrp x8, _wild_subtractor_absolute_value@PAGE
    ldr x0, [x8, _wild_subtractor_absolute_value@PAGEOFF]
    movz x1, #1, lsl #32
    cmp x0, x1
    b.ne Lfailure

    adrp x8, _wild_subtractor_private_value@PAGE
    ldr x0, [x8, _wild_subtractor_private_value@PAGEOFF]
    adrp x8, Lwild_subtractor_private_minuend@PAGE
    add x1, x8, Lwild_subtractor_private_minuend@PAGEOFF
    adrp x8, Lwild_subtractor_private_subtrahend@PAGE
    add x2, x8, Lwild_subtractor_private_subtrahend@PAGEOFF
    sub x1, x1, x2
    add x1, x1, #5
    cmp x0, x1
    b.ne Lfailure

    mov w0, #42
    b _exit_syscall
Lfailure:
    mov w0, #1
    b _exit_syscall

.section __DATA,__data
.p2align 3
.globl _wild_subtractor_local_subtrahend
_wild_subtractor_local_subtrahend:
    .quad 0
.globl _wild_subtractor_local_value
_wild_subtractor_local_value:
    .quad _wild_subtractor_local_minuend - _wild_subtractor_local_subtrahend + 17
.globl _wild_subtractor_external_subtrahend
_wild_subtractor_external_subtrahend:
    .quad 0
.globl _wild_subtractor_external_value
_wild_subtractor_external_value:
    .quad _wild_subtractor_external_minuend - _wild_subtractor_external_subtrahend - 9
.globl _wild_subtractor_absolute_value
_wild_subtractor_absolute_value:
    .quad _wild_subtractor_absolute_minuend - _wild_subtractor_local_subtrahend
.globl _wild_subtractor_private_value
_wild_subtractor_private_value:
    .quad Lwild_subtractor_private_minuend - Lwild_subtractor_private_subtrahend + 5
.globl _wild_subtractor_dead_atom
_wild_subtractor_dead_atom:
    .quad 0

.section __DATA_CONST,__const
.p2align 3
.globl _wild_subtractor_local_minuend
_wild_subtractor_local_minuend:
    .quad 0

.section __DATA,__private
.p2align 3
Lwild_subtractor_private_subtrahend:
    .quad 0

.section __DATA_CONST,__private
.p2align 3
Lwild_subtractor_private_minuend:
    .quad 0
