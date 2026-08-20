//#LinkerDriver:clang
//#Arch:aarch64
//#SoSingleLinker:ld
//#LinkSoArgs:-Wl,-undefined,dynamic_lookup
//#Shared:as(libdylib-undefined.dylib):provider.c
//#RunEnabled:false
//#DiffEnabled:false

// A dylib's own undefined nlist is a dyld import. The final executable uses the exported
// provider, but is intentionally not executed because `missing_from_dylib` has no runtime owner.
int dylib_undefined_provider(void);

int main(void) { return dylib_undefined_provider(); }
