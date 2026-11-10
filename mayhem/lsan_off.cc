// Leaks are not the bug class fuzzed here; ASan's memory-corruption checks and UBSan stay on.
extern "C" int __lsan_is_turned_off() { return 1; }
