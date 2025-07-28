#pragma once

#include "../../src/math/fft/fft.cuh"
#include <math.h>

#define MAX_FFT 2048
#define FFT_STORAGE 2112

template <typename T>
__device__ void can_rountrip_fft(
    const T *__restrict__ x,
    T *__restrict__ result,
    uint32_t fft_len)
{
    assert(fft_len <= MAX_FFT);

    uint32_t tid = threadIdx.x;
    uint32_t block_size = blockDim.x;
    uint32_t block_id = blockIdx.x;

    __shared__ T x_local[FFT_STORAGE];

    for (unsigned int i = tid; i < fft_len; i += block_size)
    {
        x_local[i] = x[block_id * fft_len + i];
    }

    __syncthreads();

    fft(x_local, fft_len);

    for (unsigned int i = tid; i < fft_len; i += block_size)
    {
        result[block_id * fft_len + i] = x_local[i];
    }
}

template <typename T>
__device__ void can_rountrip_ifft(
    const T *__restrict__ x,
    T *__restrict__ result,
    uint32_t fft_len)
{
    assert(fft_len <= MAX_FFT);

    uint32_t tid = threadIdx.x;
    uint32_t block_size = blockDim.x;
    uint32_t block_id = blockIdx.x;

    __shared__ T x_local[FFT_STORAGE];

    for (unsigned int i = tid; i < fft_len; i += block_size)
    {
        x_local[i] = x[block_id * fft_len + i];
    }

    __syncthreads();

    ifft(x_local, fft_len);

    for (unsigned int i = tid; i < fft_len; i += block_size)
    {
        result[block_id * fft_len + i] = x_local[i];
    }
}

extern "C" __global__ void can_rountrip_fft_f64(
    const double2 *__restrict__ x,
    double2 *__restrict__ result,
    uint32_t fft_len)
{
    can_rountrip_fft(x, result, fft_len);
}

extern "C" __global__ void can_rountrip_fft_f32(
    const float2 *__restrict__ x,
    float2 *__restrict__ result,
    uint32_t fft_len)
{
    can_rountrip_fft(x, result, fft_len);
}

extern "C" __global__ void can_rountrip_ifft_f64(
    const double2 *__restrict__ x,
    double2 *__restrict__ result,
    uint32_t fft_len)
{
    can_rountrip_ifft(x, result, fft_len);
}

extern "C" __global__ void can_rountrip_ifft_f32(
    const float2 *__restrict__ x,
    float2 *__restrict__ result,
    uint32_t fft_len)
{
    can_rountrip_ifft(x, result, fft_len);
}