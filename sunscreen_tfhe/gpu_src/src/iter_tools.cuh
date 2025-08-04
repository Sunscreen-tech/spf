#pragma once
#include <cstdint>

#define BLOCK_FOR_EACH(i, N) \
    for (uint32_t i = threadIdx.x; i < N; i += blockDim.x)
