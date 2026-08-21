// A relocation-free entry point for the stable-layout cache's linker-private symbol fixture.
.text
.globl _main
_main:
    mov w0, #42
    ret
