#pragma once
#include <cstdint>

#include "../../src/math/fft/negacyclic.cuh"
#include "../../src/math/fft/fft.cuh"

extern "C" __global__ void can_forward_twisted_fft_f64(
    const double *__restrict__ input,
    double2 * __restrict__ output,
    uint32_t n
) {
    __shared__ double2 result[FFT_STORAGE];

    twisted_fft(&input[blockIdx.x * n], result, n);

    for (uint32_t i = threadIdx.x; i < n / 2; i += blockDim.x) {
        output[blockIdx.x * n / 2 + i] = result[i];
    }
}