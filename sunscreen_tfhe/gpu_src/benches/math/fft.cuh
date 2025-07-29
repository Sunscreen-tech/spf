#pragma once
#include <cstdint>
#include "../../src/math/fft/fft.cuh"

template <typename T>
__device__ void benchmark_fft(
    const T *__restrict__ x,
    T *__restrict__ result,
    uint32_t fft_len,
    uint32_t fft_count
) {
    assert(fft_len <= MAX_FFT);

    uint32_t tid = threadIdx.x;
    uint32_t block_size = blockDim.x;
    uint32_t block_id = blockIdx.x;

    __shared__ T x_local[FFT_STORAGE];

    for (unsigned int i = tid; i < fft_len; i += block_size)
    {
        x_local[i] = x[block_id * fft_len + i];
    }

    __syncthreads();

    for (uint32_t i = 0; i < fft_count; i++) {
        fft_noreorder(x_local, fft_len);
    }

    for (unsigned int i = tid; i < fft_len; i += block_size)
    {
        result[block_id * fft_len + i] = x_local[i];
    }
}

extern "C" __global__ void benchmark_fft_f64(
    double2* in,
    double2* out,
    uint32_t fft_len,
    uint32_t fft_count
) {
    benchmark_fft(in, out, fft_len, fft_count);
}

extern "C" __global__ void benchmark_fft_f32(
    float2* in,
    float2* out,
    uint32_t fft_len,
    uint32_t fft_count
) {
    benchmark_fft(in, out, fft_len, fft_count);
}