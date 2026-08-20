//#LinkerDriver:clang

_Thread_local int dynamic_tls = 40;
// Keep enough zero-fill TLS storage to cross a Mach-O page boundary. `__thread_bss` belongs to
// __DATA, so a following __LINKEDIT segment must start after this allocation rather than at the
// pre-TLS cursor. The volatile write below retains it with -dead_strip.
_Thread_local volatile unsigned char dynamic_tls_zero_fill[0x4000];

int producer_increment(void) {
  dynamic_tls_zero_fill[sizeof(dynamic_tls_zero_fill) - 1] = 1;
  return ++dynamic_tls;
}
int producer_read(void) { return dynamic_tls; }
