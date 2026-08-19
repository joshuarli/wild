.globl _target
.p2align 2
_target:
    mov w0, #42
    b _exit_syscall
