//#LinkerDriver:clang
//#LinkArgs:-framework CoreFoundation
//#Contains:CoreFoundation.framework
//#DiffIgnore:section.__unwind_info

// A second SDK framework has a distinct TAPI and install-name path from Security. Accessing the
// exported constant as well as calling two framework functions exercises both chained data and
// function imports through the normal `-F` / `-framework` lookup path.
#include <CoreFoundation/CoreFoundation.h>

int main(void) {
  return CFGetTypeID(kCFBooleanTrue) == CFBooleanGetTypeID() ? 42 : 1;
}
