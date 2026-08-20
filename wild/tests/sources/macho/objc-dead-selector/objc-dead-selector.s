//#LinkerDriver:clang
//#LinkArgs:-lobjc -Wl,-dead_strip
//#NoSection:__objc_stubs
//#NoSection:__objc_selrefs

// Keep this as a minimal assembler input so only the dead atom owns the modern selector-send
// relocation. Clang's Objective-C class metadata has its own root rules, which would obscure the
// contract under test here.
.subsections_via_symbols

.section __TEXT,__text,regular,pure_instructions
.globl _main
.p2align 2
_main:
    mov w0, #42
    ret

.private_extern _dead_selector_send
.p2align 2
_dead_selector_send:
    bl _objc_msgSend$deadSelector
    ret

.section __TEXT,__objc_methname,cstring_literals
L_dead_selector:
    .asciz "deadSelector"
