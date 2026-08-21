// Same __text footprint as `main.s`, with changed instruction bytes but no symbol movement.
.text
.globl _main
_main:
    mov w0, #42
    br x30
