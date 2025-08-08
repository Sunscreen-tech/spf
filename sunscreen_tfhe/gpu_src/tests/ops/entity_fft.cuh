#pragma once
#include <cstdint>

#include "../../src/entities/dst_array.cuh"
#include "../../src/entities/glwe.cuh"

extern "C" __global__ void compare_glwe_fft(
    DstArray<GlweCiphertext<uint64_t>> *__restrict__ c,
    DstArray<GlweCiphertextFft<Complex<double>>> *__restrict__ c_fft,
    const DstArray<GlweCiphertext<uint64_t>> *__restrict__ x
) {
    const auto &glwe = GLWE_1_2048_128;

    auto x_i = x->nth(blockIdx.x, glwe);
    auto c_i = c->nth(blockIdx.x, glwe);
    auto c_fft_i = c_fft->nth(blockIdx.x, glwe);

    x_i->fft(c_fft_i, glwe);
    c_fft_i->ifft(c_i, glwe);
}