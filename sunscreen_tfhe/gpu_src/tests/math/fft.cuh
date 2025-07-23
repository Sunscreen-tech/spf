#pragma once

#include "../../src/math/fft/fft.cuh"

template<uint32_t FFT_LEN> 
__global__ void can_rountrip_fft_impl(
    const double2* __restrict__ x,
    double2* __restrict__ result
) {
    __shared__ double2 x_local[FFT_LEN];

    uint32_t tid = threadIdx.x;
    uint32_t block_size = blockDim.x;
    uint32_t block_id = blockIdx.x;

    for (unsigned int i = 0; i < FFT_LEN; i += block_size) {
        x_local[i] = x[block_id * FFT_LEN + i];
    }

    __syncthreads();

    fft(x_local, FFT_LEN);
    ifft(x_local, FFT_LEN);

    for (unsigned int i = 0; i < FFT_LEN; i += block_size) {
        result[block_id * FFT_LEN + i] = x_local[i];
    }
}