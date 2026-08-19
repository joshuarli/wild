//#Object:padding-1a.s
//#Object:padding-1b.s
//#Object:middle.s
//#Object:padding-2a.s
//#Object:padding-2b.s
//#Object:target.s
//#Object:runtime.c

// The first far branch needs an island after this object. `_middle` is deliberately reached only
// through that first island, so it starts after the first padding and independently exercises a
// second owner block for its branch to `_target`.
.globl _main
.p2align 2
_main:
    b _middle
