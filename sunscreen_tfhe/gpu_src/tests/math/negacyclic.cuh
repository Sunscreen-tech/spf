#pragma once
#include <cstdint>

#include "../../src/math/math.cuh"
#include "../../src/math/fft/negacyclic.cuh"
#include "../../src/math/fft/fft.cuh"

extern "C" __global__ void can_apply_twist(
    const double* __restrict__ input,
    Complex<double>* __restrict__ output,
    uint32_t n
) {
    auto s_in = get_fft_scratch<double>();

    BLOCK_COPY(s_in, &input[blockIdx.x * n], n);

    auto s_out = apply_twist(s_in, n);

    BLOCK_COPY(&output[blockIdx.x * n / 2], s_out, n / 2);
}

extern "C" __global__ void can_remove_twist(
    const Complex<double>* __restrict__ input,
    double* __restrict__ output,
    uint32_t n
) {
    auto s_in = get_fft_scratch<Complex<double>>();

    BLOCK_COPY(s_in, &input[blockIdx.x * n / 2], n / 2);

    auto s_out = remove_twist(s_in, n);

    BLOCK_COPY(&output[blockIdx.x * n], s_out, n);
}