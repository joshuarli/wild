// Same __text footprint as `local.s`, but the linker-private symbol is four bytes later.
.text
.private_extern _stable_layout_local_target
    .space 4
_stable_layout_local_target:
    nop
    .space 8
