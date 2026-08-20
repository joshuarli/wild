//#Config:default
//#LinkerDriver:clang
//#LinkArgs:-Wl,-dead_strip
//#Object:dead-strip-10000.s
//#ExpectSym:_wild_dead_strip_stress_live
//#NoSym:_wild_dead_strip_stress_first
//#NoSym:_wild_dead_strip_stress_last
//#DiffIgnore:section.__unwind_info

extern int wild_dead_strip_stress_live(void);

int main(void) { return wild_dead_strip_stress_live(); }
