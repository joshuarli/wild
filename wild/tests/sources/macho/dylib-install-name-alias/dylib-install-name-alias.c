//#LinkArgs:-dylib -dylib_install_name @rpath/libdylib-install-name-alias.dylib
//#RunDynSym:dylib_install_name_alias
//#Contains:@rpath/libdylib-install-name-alias.dylib

// Clang and ld64 spell this option `-dylib_install_name`; it must be equivalent to -install_name.
int dylib_install_name_alias(void) { return 42; }
