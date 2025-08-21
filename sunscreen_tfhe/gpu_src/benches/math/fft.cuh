#pragma once
#include <cstdint>
#include "../../src/math/fft/fft.cuh"
#include "../../src/entities/polynomial.cuh"

template <typename T>
__device__ void benchmark_fft(
    const Complex<T> *__restrict__ x,
    Complex<T> *__restrict__ result,
    u32 fft_len,
    u32 fft_count,
    u32 reorder
) {
    u32 block_id = blockIdx.x;

    auto x_local = get_fft_scratch<Complex<T>>();

    BLOCK_COPY(x_local, &x[block_id * fft_len], fft_len);

    for (u32 i = 0; i < fft_count; i++) {
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
    u32 fft_len,
    u32 fft_count,
    u32 reorder
) {
    benchmark_fft(in, out, fft_len, fft_count, reorder);
}

extern "C" __global__ void benchmark_fft_f32(
    const Complex<float>* __restrict__ in,
    Complex<float>* __restrict__ out,
    u32 fft_len,
    u32 fft_count,
    u32 reorder
) {
    benchmark_fft(in, out, fft_len, fft_count, reorder);
}

extern "C" __global__ void benchmark_fft_polynomial(
    const Polynomial<uint64_t> *__restrict__ in,
    Polynomial<Complex<double>> *__restrict__ out,
    u32 fft_count
) {
    const auto len = PolynomialDegree(2048);
    auto s_in = get_fft_scratch<Polynomial<uint64_t>>();

    BLOCK_COPY(s_in, in, len.val);

    for (u32 i = 0; i < fft_count; i++) {
        s_in->fft_inplace<Complex<double>>(len);
    }
}