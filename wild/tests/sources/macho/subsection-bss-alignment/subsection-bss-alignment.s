//#Object:runtime.c
//#LinkerDriver:clang
//#LinkArgs:-Wl,-dead_strip
//#ExpectSym:_wild_subsection_bss_first alignment=1
//#ExpectSym:_wild_subsection_bss_aligned alignment=8
//#NoSym:_wild_subsection_bss_dead
//#DiffIgnore:section.__unwind_info

// `MH_SUBSECTIONS_VIA_SYMBOLS` lets dead stripping remove the middle atom. The final atom still
// has an 8-byte input address, so its compacted address must retain that alignment rather than
// follow the one-byte live atom directly.
.subsections_via_symbols
.globl _main
.p2align 2
_main:
    adrp x0, _wild_subsection_bss_first@PAGE
    add x0, x0, _wild_subsection_bss_first@PAGEOFF
    adrp x1, _wild_subsection_bss_aligned@PAGE
    add x1, x1, _wild_subsection_bss_aligned@PAGEOFF
    mov w0, #42
    b _exit_syscall

.section __DATA,__bss
.globl _wild_subsection_bss_first
_wild_subsection_bss_first:
    .space 1
.globl _wild_subsection_bss_dead
_wild_subsection_bss_dead:
    .space 7
.p2align 3
.globl _wild_subsection_bss_aligned
_wild_subsection_bss_aligned:
    .space 8
