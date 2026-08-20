// This throwing frame lives in an archive member. The final link must retain its LSDA and
// compact-unwind row when the undefined C ABI entry point extracts the member.
extern "C" __attribute__((noinline)) void wild_cxx_exception_archive_throw() { throw 42; }

static __attribute__((noinline)) int wild_cxx_exception_archive_unused() { return 7; }
