//#Arch:aarch64
//#LinkerDriver:clang
//#SoSingleLinker:ld
//#Shared:provider.c
//#DiffIgnore:section.__unwind_info

// Default Mach-O output uses the two-level namespace. The executable deliberately defines the
// same public name, but the dylib's ordinary self-call must remain bound to its own definition.
int dylib_twolevel_self_call(void);
int dylib_twolevel_value(void) { return 41; }

int main(void) { return dylib_twolevel_self_call() == 1 ? 42 : 1; }
