#pragma once
#include "fft_f32_impl.cuh"
#include "fft_f64_impl.cuh"
#include "fft_params.cuh"
#include "../math.cuh"

#include <cstdint>

#define MAX_FFT 1024
#define FFT_STORAGE 1056

template <typename T>
__device__ void fft(Complex<T> *s_input, uint32_t n)
{
    using VecT = typename Complex<T>::VecT;

    switch (n)
    {
    case 1024:
        do_SMFFT_CT_DIT<FFT_1024_forward>(reinterpret_cast<VecT*>(s_input));
        break;
    default:
        printf("Illegal FFT size %d", n);
        assert(false);
    }

    __syncthreads();
}

template <typename T>
__device__ void ifft(Complex<T> *s_input, uint32_t n)
{
    using VecT = typename Complex<T>::VecT;

    switch (n)
    {
    case 1024:
        do_SMFFT_CT_DIT<FFT_1024_inverse>(reinterpret_cast<VecT*>(s_input));
        break;
    default:
        printf("Illegal FFT size %d", n);
        assert(false);
    }

    __syncthreads();
}


template <typename T>
__device__ void fft_noreorder(Complex<T> *s_input, uint32_t n)
{
    using VecT = typename Complex<T>::VecT;

    switch (n)
    {
    case 1024:
        do_SMFFT_CT_DIT<FFT_1024_forward_noreorder>(reinterpret_cast<VecT*>(s_input));
        break;
    default:
        printf("Illegal FFT size %d", n);
        assert(false);
    }

    __syncthreads();
}

template <typename T>
__device__ void ifft_noreorder(Complex<T> *s_input, uint32_t n)
{
    using VecT = typename Complex<T>::VecT;

    switch (n)
    {
    case 1024:
        do_SMFFT_CT_DIT<FFT_1024_inverse_noreorder>(reinterpret_cast<VecT>(s_input));
        break;
    default:
        printf("Illegal FFT size %d", n);
        assert(false);
    }

    __syncthreads();
}