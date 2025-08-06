// We include everything as headers so we don't have to fool with LTO and can just
// build everything as a single compilation unit.

#ifdef TEST
#include "tests/tests.cuh"
#include "benches/benches.cuh"
#endif
