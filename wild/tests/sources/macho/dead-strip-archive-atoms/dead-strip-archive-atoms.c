//#Config:default
//#LinkerDriver:clang
//#LinkArgs:-Wl,-dead_strip
//#Object:runtime.c
//#Archive:dead-strip-archive-member.c
//#ExpectSym:_wild_dead_strip_archive_live
//#NoSym:_wild_dead_strip_archive_dead
//#NoSym:_wild_dead_strip_archive_dead_data
//#DiffIgnore:section.__unwind_info

#include "../common/runtime.h"

int wild_dead_strip_archive_live(void);

void main(void) { exit_syscall(wild_dead_strip_archive_live()); }
