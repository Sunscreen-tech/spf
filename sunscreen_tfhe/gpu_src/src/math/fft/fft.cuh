#pragma once
#include <complex>
#include <cstdint>

#include "fft_noreorder.cuh"
#include "fft_f32_impl.cuh"
#include "fft_f64_impl.cuh"
#include "fft_params.cuh"
#include "../math.cuh"
#include "../primitives.cuh"

const size_t FFT_BUFFER_SIZE = 3 * 1024;
__shared__ std::complex<double> FFT_BUFFER[FFT_BUFFER_SIZE];

__device__ constexpr PunBuf get_fft_scratch() {
    return PunBuf::from_ptr(FFT_BUFFER);
}

__device__ void fft_noreorder(std::complex<f64> *s_input, uint32_t n)
{
    switch (n)
    {
    case 1024:
        // TODO: Remove this UB
        CT_DIF_FFT_4way<FFT_1024_forward_noreorder>(reinterpret_cast<double2 *>(s_input));
        break;
    default:
        printf("Illegal FFT size %d", n);
        assert(false);
    }

    __syncthreads();
}

__device__ void ifft_noreorder(std::complex<f64> *s_input, uint32_t n)
{
    switch (n)
    {
    case 1024:
        // TODO: Remove this UB
        CT_DIT_FFT_4way<FFT_1024_inverse_noreorder>(reinterpret_cast<double2 *>(s_input));
        break;
    default:
        printf("Illegal FFT size %d", n);
        assert(false);
    }

    __syncthreads();
}