//#LinkerDriver:clang
//#LinkArgs:-Wl,-dead_strip
//#NoSym:_wild_dead_strip_unused_function
//#NoSym:_wild_dead_strip_unused_data
//#ExpectSym:_wild_dead_strip_live_function
//#ExpectSym:_wild_dead_strip_live_data

// Clang's Darwin object writer marks this object MH_SUBSECTIONS_VIA_SYMBOLS. The live function
// references live data; the two unused global atoms make the test observe both atom liveness and
// final symbol-table filtering rather than merely the process exit status.
__attribute__((noinline)) int wild_dead_strip_live_function(void) {
  return 19;
}

__attribute__((noinline)) int wild_dead_strip_unused_function(void) {
  return 7;
}

int wild_dead_strip_live_data = 23;
int wild_dead_strip_unused_data = 29;

int main(void) {
  return wild_dead_strip_live_function() + wild_dead_strip_live_data;
}
