//#Config:default
//#LinkerDriver:clang
//#DiffIgnore:section.__unwind_info
//#LinkArgs:-Wl,-dead_strip
//#Shared:tls-dynamic-producer.c

// An imported Mach-O TLV must be reached through a runtime-bound TLVP slot.  A plain GOT entry
// is not equivalent: the bootstrap uses the imported descriptor to select distinct storage for
// each thread.  Exercise the descriptor from the consumer and from the producer on two threads.
#include <pthread.h>

extern _Thread_local int dynamic_tls;
int producer_increment(void);
int producer_read(void);

static void *thread_entry(void *ignored) {
  (void)ignored;
  dynamic_tls = 70;
  if (producer_increment() != 71 || producer_read() != 71 || dynamic_tls != 71) {
    return (void *)1;
  }
  return 0;
}

int main(void) {
  pthread_t thread;
  if (dynamic_tls != 40 || producer_increment() != 41 || dynamic_tls != 41) {
    return 1;
  }
  if (pthread_create(&thread, 0, thread_entry, 0) != 0) {
    return 2;
  }
  void *thread_result = 0;
  if (pthread_join(thread, &thread_result) != 0 || thread_result != 0) {
    return 3;
  }
  return dynamic_tls == 41 && producer_read() == 41 ? 42 : 4;
}
