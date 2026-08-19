//#Config:default
//#TestUpdateInPlace:true
//#Object:runtime.c

// Force ARM64_RELOC_GOT_LOAD_PAGE21/PAGEOFF12 for a definition in this image. The resulting
// `__DATA_CONST,__got` slot must be a chained rebase, not an imported bind and not zero-filled.
.globl _main
.p2align 2
_main:
    adrp x0, _target@GOTPAGE
    ldr x0, [x0, _target@GOTPAGEOFF]
    blr x0
    b _exit_syscall

.p2align 2
_target:
    mov w0, #42
    ret
