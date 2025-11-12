#pragma once
#include <cuda/std/complex>

#include "../../features.cuh"

#include "fft_noreorder.cuh"

#include "fft_params.cuh"
#include "../math.cuh"
#include "../primitives.cuh"

template <typename T>
__device__ void fft_noreorder(cuda::std::complex<T> *s_input, u32 n, cuda::std::complex<T> *twiddles_inv)
{
    __syncthreads();
    
    switch (n)
    {
    case 1024:
        CT_DIF_FFT_4way<FFT_1024_forward_noreorder, T>(s_input, twiddles_inv);
        break;
    default:
        printf("Illegal FFT size %d", n);
        assert(false);
    }

    __syncthreads();
}

template <typename T>
__device__ void ifft_noreorder(cuda::std::complex<T> *s_input, u32 n, cuda::std::complex<T> *twiddles)
{
    __syncthreads();

    switch (n)
    {
    case 1024:
        CT_DIT_FFT_4way< FFT_1024_inverse_noreorder, T>(s_input, twiddles);
        break;
    default:
        printf("Illegal FFT size %d", n);
        assert(false);
    }

    __syncthreads();
}