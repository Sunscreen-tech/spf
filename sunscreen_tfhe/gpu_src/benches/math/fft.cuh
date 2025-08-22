#pragma once
#include <cuda/std/complex>

#include "../../src/math/fft/fft.cuh"
#include "../../src/entities/polynomial.cuh"
#include "../../src/math/primitives.cuh"

template <typename T>
__device__ void benchmark_fft(
    const cuda::std::complex<T> *__restrict__ x,
    cuda::std::complex<T> *__restrict__ result,
    u32 fft_len,
    u32 fft_count
) {
    u32 block_id = blockIdx.x;

    __shared__ cuda::std::complex<T> x_local[2048];
    auto s_p = &x_local[1024 * threadIdx.y];

    BLOCK_COPY(x_local, &x[block_id * fft_len], fft_len);

    for (u32 i = 0; i < fft_count; i++) {
        fft_noreorder(s_p, fft_len);
    }

    BLOCK_COPY(&result[block_id * fft_len], x_local, fft_len);
}

extern "C" __global__ void benchmark_fft_f64(
    const cuda::std::complex<double>* __restrict__ in,
    cuda::std::complex<double>* __restrict__ out,
    u32 fft_len,
    u32 fft_count
) {
    benchmark_fft(in, out, fft_len, fft_count);
}

extern "C" __global__ void benchmark_fft_f32(
    const cuda::std::complex<float>* __restrict__ in,
    cuda::std::complex<float>* __restrict__ out,
    u32 fft_len,
    u32 fft_count
) {
    benchmark_fft(in, out, fft_len, fft_count);
}
/*
extern "C" __global__ void benchmark_fft_polynomial(
    const Polynomial<uint64_t> *__restrict__ in,
    Polynomial<cuda::std::complex<double>> *__restrict__ out,
    u32 fft_count
) {
    const auto len = PolynomialDegree(2048);
    auto s_in = get_fft_scratch<Polynomial<uint64_t>>();

    BLOCK_COPY(s_in, in, len.val);

    for (u32 i = 0; i < fft_count; i++) {
        s_in->fft_inplace<cuda::std::complex<double>>(len);
    }
}*/