// The archive member must first be lazily extracted for its live symbol, then its own
// `MH_SUBSECTIONS_VIA_SYMBOLS` atoms must still be eligible for `-dead_strip` independently.
__attribute__((noinline)) int wild_dead_strip_archive_live(void) { return 42; }

__attribute__((noinline)) int wild_dead_strip_archive_dead(void) { return 1; }

int wild_dead_strip_archive_dead_data = 1;
