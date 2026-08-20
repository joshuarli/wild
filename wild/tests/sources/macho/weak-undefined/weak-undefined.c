//#ExpectError:(?s)(symbol.*wild_missing_weak|wild_missing_weak.*symbol)

// A Mach-O weak import is optional only with respect to a linked dylib. It must not turn a
// completely unprovided symbol into an accepted executable; `N_WEAK_REF` is an import-property,
// not an undefined-symbol escape hatch.
extern int wild_missing_weak(void) __attribute__((weak_import));

int main(void) {
  return wild_missing_weak ? wild_missing_weak() : 1;
}
