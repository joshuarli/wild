//#LinkArgs:-dylib -dylib_install_name @rpath/libdylib-local-rebase.dylib
//#RunDynSym:dylib_local_rebase

// A dylib's local pointer must be rebased by dyld after the image is loaded away from zero.
// This specifically covers the MH_DYLIB VM base and chained-rebase table rather than an
// executable's synthetic __PAGEZERO layout.
static int target(void) {
  return 42;
}

static int (*const target_pointer)(void) = target;

int dylib_local_rebase(void) {
  return target_pointer();
}
