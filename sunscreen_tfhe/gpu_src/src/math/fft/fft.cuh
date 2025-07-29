#pragma once
#include "fft_f32_impl.cuh"
#include "fft_f64_impl.cuh"
#include "fft_params.cuh"
#include <cstdint>

#define MAX_FFT 2048
#define FFT_STORAGE 2112

template <typename Complex>
__device__ void fft(Complex *s_input, uint32_t n)
{
    switch (n)
    {
    case 1024:
        do_SMFFT_CT_DIT<FFT_1024_forward>(s_input);
        break;
    case 2048:
        do_SMFFT_CT_DIT<FFT_2048_forward>(s_input);
        break;
    default:
        printf("Illegal FFT size %d", n);
        assert(false);
    }

    __syncthreads();
}

template <typename Complex>
__device__ void ifft(Complex *s_input, uint32_t n)
{
    switch (n)
    {
    case 1024:
        do_SMFFT_CT_DIT<FFT_1024_inverse>(s_input);
        break;
    case 2048:
        do_SMFFT_CT_DIT<FFT_2048_inverse>(s_input);
        break;
    default:
        printf("Illegal FFT size %d", n);
        assert(false);
    }

    __syncthreads();
}


template <typename Complex>
__device__ void fft_noreorder(Complex *s_input, uint32_t n)
{
    switch (n)
    {
    case 1024:
        do_SMFFT_CT_DIT<FFT_1024_forward_noreorder>(s_input);
        break;
    case 2048:
        do_SMFFT_CT_DIT<FFT_2048_forward_noreorder>(s_input);
        break;
    default:
        printf("Illegal FFT size %d", n);
        assert(false);
    }

    __syncthreads();
}

template <typename Complex>
__device__ void ifft_noreorder(Complex *s_input, uint32_t n)
{
    switch (n)
    {
    case 1024:
        do_SMFFT_CT_DIT<FFT_1024_inverse_noreorder>(s_input);
        break;
    case 2048:
        do_SMFFT_CT_DIT<FFT_2048_inverse_noreorder>(s_input);
        break;
    default:
        printf("Illegal FFT size %d", n);
        assert(false);
    }

    __syncthreads();
}