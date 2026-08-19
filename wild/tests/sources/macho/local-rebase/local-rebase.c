//#Config:default
//#LinkerDriver:clang
//#TestUpdateInPlace:true

// This is deliberately writable data: the ARM64 object contains a 64-bit
// ARM64_RELOC_UNSIGNED relocation in __DATA,__data. Under PIE/ASLR dyld must slide this local
// function pointer through a chained rebase; a GOT-only chain leaves the link-time address here.
static int target(void) {
  return 42;
}

static int (*pointer)(void) = target;

int main(void) {
  return pointer();
}
