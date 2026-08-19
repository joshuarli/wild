//#Object:padding-1.s
//#Object:padding-2.s
//#Object:target.s
//#Object:runtime.c

// The two padding objects put the direct target outside ARM64's +/-128 MiB B/BL range. Keeping
// every input atom below a cluster lets Apple ld create its own reference island. Wild must
// redirect this unconditional branch to a primary `__TEXT,__text` island; there are no imports,
// so using the dyld-owned `__stubs` section would be both semantically wrong and visibly fail.
.globl _main
.p2align 2
_main:
    b _target
