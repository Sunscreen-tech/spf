#pragma once
#include <cstdint>

#define BLOCK_FOR_EACH(i, N) \
    for (uint32_t i = threadIdx.x; i < N; i += blockDim.x)

#define COPY_TO_LOCAL(s_ptr, g_ptr, N) \
BLOCK_FOR_EACH(i, N) \
{ \
    (s_ptr)[i] = (g_ptr)[i]; \
} \
__syncthreads();


#define COPY_FROM_LOCAL(g_ptr, s_ptr, N) \
BLOCK_FOR_EACH(i, N) \
{ \
    (g_ptr)[i] = (s_ptr)[i]; \
} \
__syncthreads();
