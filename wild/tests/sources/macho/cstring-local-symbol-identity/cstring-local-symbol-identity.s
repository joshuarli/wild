//#Object:cstring-local-symbol-identity-prefix.s
//#Object:cstring-local-symbol-identity-a.s
//#Object:cstring-local-symbol-identity-b.s
//#Object:runtime.c
//#LinkerDriver:clang
//#LinkArgs:-Wl,-dead_strip
//#DiffIgnore:section.__unwind_info

// Each input object has the same local cstring slot layout. The target slot follows a shared
// prefix, so its section-relative offset is identical in both objects even though its contents
// differ. The direct ADRP/ADD relocations must retain the input section identity when cstrings
// are merged; resolving either symbol through another object's offset would return the wrong byte.
.subsections_via_symbols

.section __TEXT,__text,regular,pure_instructions
.p2align 2
.globl _main
_main:
    bl _wild_cstring_identity_prefix
    mov x20, x0
    bl _wild_cstring_identity_a
    mov x19, x0
    bl _wild_cstring_identity_b

    ldrb w8, [x20]
    cmp w8, #'P'
    b.ne Lfailure
    ldrb w8, [x19]
    cmp w8, #'A'
    b.ne Lfailure
    ldrb w8, [x0]
    cmp w8, #'B'
    b.ne Lfailure

    mov w0, #42
    b _exit_syscall
Lfailure:
    mov w0, #1
    b _exit_syscall
