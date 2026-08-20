int missing_from_dylib(void);

int dylib_undefined_provider(void) { return missing_from_dylib(); }
