#pragma once
#include <cstdint>
#include "../../src/math/fft/fft.cuh"
#include "../../src/entities/polynomial.cuh"

template <typename T>
__device__ void benchmark_fft(
    const Complex<T> *__restrict__ x,
    Complex<T> *__restrict__ result,
    uint32_t fft_len,
    uint32_t fft_count,
    uint32_t reorder
) {
    uint32_t block_id = blockIdx.x;

    auto x_local = get_fft_scratch<Complex<T>>();

    BLOCK_COPY(x_local, &x[block_id * fft_len], fft_len);

    for (uint32_t i = 0; i < fft_count; i++) {
        if (reorder) {
            fft(x_local, fft_len);
        } else {
            fft_noreorder(x_local, fft_len);
        }
    }

    BLOCK_COPY(&result[block_id * fft_len], x_local, fft_len);
}

extern "C" __global__ void benchmark_fft_f64(
    const Complex<double>* __restrict__ in,
    Complex<double>* __restrict__ out,
    uint32_t fft_len,
    uint32_t fft_count,
    uint32_t reorder
) {
    benchmark_fft(in, out, fft_len, fft_count, reorder);
}

extern "C" __global__ void benchmark_fft_f32(
    const Complex<float>* __restrict__ in,
    Complex<float>* __restrict__ out,
    uint32_t fft_len,
    uint32_t fft_count,
    uint32_t reorder
) {
    benchmark_fft(in, out, fft_len, fft_count, reorder);
}