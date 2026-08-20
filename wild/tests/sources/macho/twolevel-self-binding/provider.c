// Keep both bodies out of the frontend's inliner so the linker's binding decision is observable.
__attribute__((noinline)) int dylib_twolevel_value(void) { return 1; }

__attribute__((noinline)) int dylib_twolevel_self_call(void) {
    return dylib_twolevel_value();
}
