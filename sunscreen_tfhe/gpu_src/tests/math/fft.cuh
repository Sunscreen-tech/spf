#pragma once

#include "../../src/math/math.cuh"
#include "fft_constants_f64.cuh"
#include "../../src/math/fft/fft.cuh"
#include "../../src/entities/dst.cuh"
#include "../../src/entities/polynomial.cuh"

template <typename T>
__device__ void can_rountrip_fft(
    const Complex<T> *__restrict__ x,
    Complex<T> *__restrict__ result,
    uint32_t fft_len)
{
    uint32_t tid = threadIdx.x;
    uint32_t block_size = blockDim.x;
    uint32_t block_id = blockIdx.x;

    init_scratch();
    auto x_local_allocation = scratch_alloc<Polynomial<Complex<T>>>(PolynomialDegree{fft_len});
    auto x_local = x_local_allocation->coeffs();
    //__shared__ Complex<T> x_local[FFT_STORAGE];

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
    const Complex<T> *__restrict__ x,
    Complex<T> *__restrict__ result,
    uint32_t fft_len)
{
    uint32_t tid = threadIdx.x;
    uint32_t block_size = blockDim.x;
    uint32_t block_id = blockIdx.x;

    init_scratch();
    auto x_local_allocation = scratch_alloc<Polynomial<Complex<T>>>(PolynomialDegree{fft_len});
    auto x_local = x_local_allocation->coeffs();
    //__shared__ Complex<T> x_local[FFT_STORAGE];

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
    const Complex<double> *__restrict__ x,
    Complex<double> *__restrict__ result,
    uint32_t fft_len)
{
    can_rountrip_fft(x, result, fft_len);
}

extern "C" __global__ void can_rountrip_fft_f32(
    const Complex<float> *__restrict__ x,
    Complex<float> *__restrict__ result,
    uint32_t fft_len)
{
    can_rountrip_fft(x, result, fft_len);
}

extern "C" __global__ void can_rountrip_ifft_f64(
    const Complex<double> *__restrict__ x,
    Complex<double> *__restrict__ result,
    uint32_t fft_len)
{
    can_rountrip_ifft(x, result, fft_len);
}

extern "C" __global__ void can_rountrip_ifft_f32(
    const Complex<float> *__restrict__ x,
    Complex<float> *__restrict__ result,
    uint32_t fft_len)
{
    can_rountrip_ifft(x, result, fft_len);
}

/// Computes the FFT twiddles using 3 methods:
/// 1. Using a pre-computed LUT that should be correctly rounded f64 values.
/// 2. Using CUDA's sincos function.
/// 3. Using CUDA's sincospi function.
extern "C" __global__ void get_twiddles_f64(
    double2 *__restrict__ method_lut,
    double2 *__restrict__ method_sincos,
    double2 *__restrict__ method_sincospi,
    uint32_t n,
    uint32_t inverse
) {
    for (uint32_t i = threadIdx.x; i < n; i += blockDim.x) {
        if (!inverse) {
            method_lut[i] = TWIDDLES_F64[n - 2 + i];
            double2 val;
            sincos(-TAU * (double)i / (double)n, &val.y, &val.x);
            method_sincos[i] = val;
            sincospi(-2.0 * (double)i / (double)n, &val.y, &val.x);
            method_sincospi[i] = val;
        } else {
            method_lut[i] = TWIDDLES_INV_F64[n - 2 + i];
            double2 val;
            sincos(TAU * (double)i / (double)n, &val.y, &val.x);
            method_sincos[i] = val;
            sincospi(2.0 * (double)i / (double)n, &val.y, &val.x);
            method_sincospi[i] = val;
        }
    }
}