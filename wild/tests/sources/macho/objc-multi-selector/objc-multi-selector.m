//#LinkerDriver:clang
//#LinkArgs:-framework Foundation -Wl,-dead_strip
//#ExpectSection:__objc_stubs size=96
//#ExpectSection:__objc_selrefs size=24

#import <Foundation/Foundation.h>

@interface WildObjcMultiSelector : NSObject
- (int)aaaSelector;
- (int)mmmSelector;
- (int)zzzSelector;
@end

@implementation WildObjcMultiSelector
- (int)aaaSelector { return 10; }
- (int)mmmSelector { return 11; }
- (int)zzzSelector { return 11; }
@end

int main(void) {
    @autoreleasepool {
        WildObjcMultiSelector *object = [[WildObjcMultiSelector alloc] init];
        // Send in deliberately non-lexical order and repeat one selector. ld64 emits one stub
        // and one selector reference per distinct spelling, ordered by selector bytes.
        int total = [object zzzSelector] + [object aaaSelector] + [object mmmSelector]
            + [object aaaSelector];
        return total == 42 ? 42 : 1;
    }
}
