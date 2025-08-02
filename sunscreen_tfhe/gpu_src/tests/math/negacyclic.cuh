#pragma once
#include <cstdint>

#include "../../src/math/math.cuh"
#include "../../src/math/fft/negacyclic.cuh"
#include "../../src/math/fft/fft.cuh"

extern "C" __global__ void can_forward_twisted_fft_f64(
    const double *__restrict__ input,
    Complex<double> * __restrict__ output,
    uint32_t n
) {
    __shared__ Complex<double> result[FFT_STORAGE];

    twisted_fft(&input[blockIdx.x * n], result, n);

    for (uint32_t i = threadIdx.x; i < n / 2; i += blockDim.x) {
        output[blockIdx.x * n / 2 + i] = result[i];
    }
}

extern "C" __global__ void can_inverse_twisted_fft_f64(
    Complex<double> *__restrict__ input,
    double * __restrict__ output,
    uint32_t n
) {
    __shared__ Complex<double> input_s[FFT_STORAGE];
    __shared__ double result[2 * FFT_STORAGE];

    for (uint32_t i = threadIdx.x; i < n / 2; i += blockDim.x) {
        input_s[i] = input[blockIdx.x * n / 2 + i];
    }

    __syncthreads();

    twisted_ifft(&input_s[blockIdx.x * n / 2], result, n);

    for (uint32_t i = threadIdx.x; i < n; i += blockDim.x) {
        output[blockIdx.x * n + i] = result[i];
    }
}