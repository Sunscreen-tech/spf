#pragma once

#if __CUDA_ARCH__ < 900
#error "This feature requires compute capability 9.0 or later"
#endif

#include "parallel_homomorphisms.cuh"