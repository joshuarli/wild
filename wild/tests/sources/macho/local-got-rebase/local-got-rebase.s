//#Config:default
//#TestUpdateInPlace:true
//#Object:runtime.c

// Force ARM64_RELOC_GOT_LOAD_PAGE21/PAGEOFF12 for a definition in this image, then also call
// that same definition directly. The resulting `__DATA_CONST,__got` slot must be a chained
// rebase, but the direct `BL` must still use the function address rather than that GOT slot.
.globl _main
.p2align 2
_main:
    adrp x0, _target@GOTPAGE
    ldr x0, [x0, _target@GOTPAGEOFF]
    blr x0
    mov w19, w0
    bl _target
    add w0, w0, w19
    b _exit_syscall

.p2align 2
_target:
    mov w0, #21
    ret
