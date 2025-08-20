#pragma once
#include <complex>

#include "../../src/math/math.cuh"
#include "fft_constants_f64.cuh"
#include "../../src/math/fft/fft.cuh"
#include "../../src/entities/polynomial.cuh"

extern "C" __global__ void can_roundtrip_fft_f64(
    const std::complex<f64> *__restrict__ x,
    std::complex<f64> *__restrict__ result,
    uint32_t fft_len)
{
    auto s_in = get_fft_scratch();

    BLOCK_COPY(s_in.as_complex(), &x[fft_len * blockIdx.x], fft_len);

    double n_inv = 1 / (double)fft_len;

    fft_noreorder(s_in.as_complex(), fft_len);
    ifft_noreorder(s_in.as_complex(), fft_len);

    BLOCK_FOR_EACH(i, fft_len)
    {
        auto val = s_in.as_complex()[i];
        val.real(val.real() * n_inv);
        val.imag(val.imag() * n_inv);

        result[fft_len * blockIdx.x + i] = val;
    }

    __syncthreads();
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