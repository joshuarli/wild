//#LinkerDriver:clang

_Thread_local int dynamic_tls = 40;

int producer_increment(void) { return ++dynamic_tls; }
int producer_read(void) { return dynamic_tls; }
