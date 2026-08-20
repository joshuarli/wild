//#LinkerDriver:clang
//#LinkArgs:-framework Foundation -Wl,-dead_strip
//#ExpectSection:__objc_stubs size=32
//#ExpectSection:__objc_selrefs size=8

#import <Foundation/Foundation.h>

// Modern libobjc TBDs keep `NSObject` in the TAPI `objc-classes` field rather than the ordinary
// `symbols` list. Clang's normal ARM64 ABI also leaves `_objc_msgSend$answer` undefined: the
// linker must synthesize a selector-reference/message stub that loads `answer` into x1 before
// branching to `_objc_msgSend`.
@interface WildObjcRuntime : NSObject
- (int)answer;
@end

@implementation WildObjcRuntime
- (int)answer { return 42; }
@end

int main(void) {
    @autoreleasepool {
        WildObjcRuntime *object = [[WildObjcRuntime alloc] init];
        return object.answer == 42 ? 42 : 1;
    }
}
