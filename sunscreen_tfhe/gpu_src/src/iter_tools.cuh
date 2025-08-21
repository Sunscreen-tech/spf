#pragma once
#include <cstdint>

/// Collectively use each thread in the current thread block to iterate [0, N).
/// In many cases, this creates optimal memory coalescing/bank conflict outcomes
/// in load and store operations.
///
/// Does not call __syncthreads();
#define BLOCK_FOR_EACH(i, N) \
    for (u32 i = threadIdx.x; i < N; i += blockDim.x)

#define BLOCK_COPY(s_ptr, g_ptr, N) \
BLOCK_FOR_EACH(i, N) \
{ \
    (s_ptr)[i] = (g_ptr)[i]; \
} \
__syncthreads();
