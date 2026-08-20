//#LinkArgs:-dylib -dylib_install_name @rpath/libdylib-export-local-got.dylib
//#RunDynSym:exported_got_target

// `exported_got_target` is externally visible, but this image also addresses it through a
// local GOT slot. dyld's export trie must name its __TEXT implementation, not that __got slot:
// `RunDynSym` calls the export through dlsym, while this helper keeps the local GOT relocation
// live in the same dylib.
.globl _exported_got_target
.p2align 2
_exported_got_target:
    mov w0, #42
    ret

.globl _keep_exported_got_live
.p2align 2
_keep_exported_got_live:
    adrp x0, _exported_got_target@GOTPAGE
    ldr x0, [x0, _exported_got_target@GOTPAGEOFF]
    br x0
