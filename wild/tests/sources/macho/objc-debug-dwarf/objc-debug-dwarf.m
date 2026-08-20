//#Arch:aarch64
//#LinkerDriver:clang
//#CompArgs:-g
//#LinkArgs:-framework Foundation -Wl,-dead_strip
//#ExpectDsymutilSymbol:_wild_objc_debug_dwarf_add
//#NoDsymutilSymbol:_wild_objc_debug_dwarf_unused
//#ExpectDsymutilLldb:function=wild_objc_debug_dwarf_add,source=objc-debug-dwarf.m,line=24
//#NoSection:__debug_info

// The Objective-C control exercises a regular receiver/send as well as the DW_LANG_ObjC map.
// The named C helper keeps the dSYM assertion stable while the class proves this is not merely a
// C translation unit with a different suffix.
#import <Foundation/Foundation.h>

@interface WildObjcDebugDwarf : NSObject
- (int)answer;
@end

@implementation WildObjcDebugDwarf
- (int)answer { return 41; }
@end

__attribute__((noinline)) int wild_objc_debug_dwarf_add(int value) {
  return value + 1;
}

static __attribute__((noinline)) int wild_objc_debug_dwarf_unused(void) {
  return 7;
}

int main(void) {
  @autoreleasepool {
    WildObjcDebugDwarf *object = [[WildObjcDebugDwarf alloc] init];
    return wild_objc_debug_dwarf_add(object.answer);
  }
}
