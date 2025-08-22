#pragma once
#include <cstdint>

#include "../../src/entities/dst_array.cuh"
#include "../../src/entities/glwe.cuh"

extern "C" __global__ void compare_glwe_fft(
    cuda::std::complex<f64> *__restrict__ c_buf,
    cuda::std::complex<f64> *__restrict__ c_fft_buf,
    const cuda::std::complex<f64> *__restrict__ x_buf
) {
    const auto &glwe = GLWE_1_2048_128;

    auto c = DstArray<GlweCiphertext>::from_ptr(c_buf);
    auto c_fft = DstArray<GlweCiphertextFft>::from_ptr(c_fft_buf);
    auto x = DstArray<GlweCiphertext>::from_ptr(x_buf);

    auto x_i = x.nth(blockIdx.x, glwe);
    auto c_i = c.nth(blockIdx.x, glwe);
    auto c_fft_i = c_fft.nth(blockIdx.x, glwe);

    x_i.fft(c_fft_i, glwe);
    c_fft_i.ifft(c_i, glwe);
}