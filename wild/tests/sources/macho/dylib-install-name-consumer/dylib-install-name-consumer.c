//#LinkerDriver:clang
//#SoSingleLinker:ld
//#LinkSoArgs:-Wl,-dylib_install_name,@loader_path/libphysical.dylib -Wl,-current_version,7.8.9 -Wl,-compatibility_version,3.2.1
//#Shared:as(libphysical.dylib):provider.c
//#ExpectMachOLoadCommand:dylib:path=@loader_path/libphysical.dylib,current=7.8.9,compatibility=3.2.1
//#Contains:@loader_path/libphysical.dylib
//#DiffIgnore:section.__unwind_info

// The dependency is opened at a physical build path, but its LC_ID_DYLIB carries this loader
// relative install name. The final consumer must use that identity and its source version pair.
int install_name_provider(void);

int main(void) { return install_name_provider(); }
