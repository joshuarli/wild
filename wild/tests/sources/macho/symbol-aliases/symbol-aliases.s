//#Object:runtime.c
//#Object:alias-target.c
//#ExpectSym:_wild_alias
//#ExpectSym:_wild_alias_target
//#NoDynSym:_wild_private_extern
//#DiffIgnore:section.__unwind_info

// Mach-O aliases are represented by multiple external symbols at one atom address. A private
// extern remains link-visible but must not appear in the executable's exports trie.
.globl _main
.p2align 2
_main:
    bl _wild_alias
    b _exit_syscall

.globl _wild_alias
.set _wild_alias, _wild_alias_target
