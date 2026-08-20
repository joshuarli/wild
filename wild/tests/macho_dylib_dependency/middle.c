int dylib_dependency_leaf_value(void);

int dylib_dependency_middle_value(void) {
  return dylib_dependency_leaf_value() + 2;
}
