#pragma once

/// Collectively use each thread in the current thread block to iterate [0, N).
/// In many cases, this creates optimal memory coalescing/bank conflict outcomes
/// in load and store operations.
///
/// Does not call __syncthreads();
#define BLOCK_FOR_EACH(i, N) \
    for (u32 i = threadIdx.x; i < N; i += blockDim.x)

/// Collectively copy from the expression g_ptr to the expression s_ptr.
/// Does not call __syncthreads();
#define BLOCK_COPY(s_ptr, g_ptr, N) \
BLOCK_FOR_EACH(i, N) \
{ \
    (s_ptr)[i] = (g_ptr)[i]; \
}

struct DimX {};
struct DimY {};
struct DimZ {};

template <typename Dim>
struct DimUtils {};

template <>
struct DimUtils<DimX> {
    __device__ static constexpr inline u32 extract(dim3 val) {
        return val.x;
    }

    __device__ static constexpr inline dim3 to_dim(u32 val, dim3 basis) {
        return {val, basis.y, basis.z};
    }
};

template <>
struct DimUtils<DimY> {
    __device__ static constexpr inline u32 extract(dim3 val) {
        return val.y;
    }

    __device__ static constexpr inline dim3 to_dim(u32 val, dim3 basis) {
        return {basis.x, val, basis.z};
    }
};

template <>
struct DimUtils<DimZ> {
    __device__ static constexpr inline u32 extract(dim3 val) {
        return val.z;
    }

    __device__ static constexpr inline dim3 to_dim(u32 val, dim3 basis) {
        return {basis.x, basis.y, val};
    }
};