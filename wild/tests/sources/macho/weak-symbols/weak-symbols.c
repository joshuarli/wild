//#LinkerDriver:clang
//#Shared:weak-symbols-provider.c
//#ExpectMachOLoadCommand:weak-dylib
//#DiffIgnore:section.__unwind_info

// `weak_import` sets N_WEAK_REF on the undefined Mach-O nlist entry. Apple links the dependency
// as LC_LOAD_WEAK_DYLIB and dyld resolves the provider when present. This runtime path also
// proves that a weak definition in the provider remains callable through the normal ARM64 stub.
extern int wild_weak_provider(void) __attribute__((weak_import));

int main(void) {
  return wild_weak_provider ? wild_weak_provider() : 1;
}
