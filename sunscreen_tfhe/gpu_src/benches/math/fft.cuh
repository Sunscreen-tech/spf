#pragma once
#include <cstdint>
#include "../../src/math/fft/fft.cuh"
#include "../../src/entities/dst.cuh"
#include "../../src/entities/polynomial.cuh"

template <typename T>
__device__ void benchmark_fft(
    const Complex<T> *__restrict__ x,
    Complex<T> *__restrict__ result,
    uint32_t fft_len,
    uint32_t fft_count
) {
    init_scratch();

    uint32_t tid = threadIdx.x;
    uint32_t block_size = blockDim.x;
    uint32_t block_id = blockIdx.x;

    //__shared__ Complex<T> x_local[FFT_STORAGE];

    // FFT requires up to 64 extra Complex<T> elements
    auto x_local_allocation = scratch_alloc<Polynomial<Complex<T>>>(PolynomialDegree(fft_len));
    auto x_local = x_local_allocation->coeffs();

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
    const Complex<double>* __restrict__ in,
    Complex<double>* __restrict__ out,
    uint32_t fft_len,
    uint32_t fft_count
) {
    benchmark_fft(in, out, fft_len, fft_count);
}

extern "C" __global__ void benchmark_fft_f32(
    const Complex<float>* __restrict__ in,
    Complex<float>* __restrict__ out,
    uint32_t fft_len,
    uint32_t fft_count
) {
    benchmark_fft(in, out, fft_len, fft_count);
}