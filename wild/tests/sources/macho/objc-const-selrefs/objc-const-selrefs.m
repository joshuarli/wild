//#LinkerDriver:clang
//#CompArgs:-fobjc-arc
//#LinkArgs:-framework Foundation -Wl,-dead_strip -Wl,-const_selrefs
//#ReferenceLinkers:ld
//#ExpectSection:__objc_stubs size=32,segment="__TEXT"
//#ExpectSection:__objc_selrefs size=8,segment="__DATA_CONST",macho_flags=0

#import <Foundation/Foundation.h>

// `-const_selrefs` changes the image-protection contract for normal ARC selector dispatch. The
// selector slot remains a dyld rebase, but it must be in __DATA_CONST so it becomes immutable
// after fixups instead of in writable __DATA.
@interface WildObjcConstSelrefs : NSObject
- (int)answer;
@end

@implementation WildObjcConstSelrefs
- (int)answer { return 42; }
@end

int main(void) {
    @autoreleasepool {
        WildObjcConstSelrefs *object = [[WildObjcConstSelrefs alloc] init];
        return object.answer == 42 ? 42 : 1;
    }
}
