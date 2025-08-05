#pragma once
#include <cstdint>

#define BLOCK_FOR_EACH(i, N) \
    for (uint32_t i = threadIdx.x; i < N; i += blockDim.x)

#define BLOCK_COPY(s_ptr, g_ptr, N) \
BLOCK_FOR_EACH(i, N) \
{ \
    (s_ptr)[i] = (g_ptr)[i]; \
} \
__syncthreads();
