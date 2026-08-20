//#Object:runtime.c
//#LinkerDriver:clang
//#LinkArgs:-framework Security
//#ExpectMachOLoadCommand:dylib:path=/System/Library/Frameworks/Security.framework/Versions/A/Security,current=61901.120.67,compatibility=1.0.0
//#DiffIgnore:section.__unwind_info

#include <Security/SecRandom.h>

#include "../common/runtime.h"

// Force both SDK framework lookup and a real Security import; merely accepting `-framework`
// would not prove that Wild resolves the framework's TBD symbols and dyld ordinal correctly.
void main(void) {
  unsigned char byte = 0;
  const int status = SecRandomCopyBytes(kSecRandomDefault, sizeof(byte), &byte);
  exit_syscall(status == 0 ? 42 : 1);
}
