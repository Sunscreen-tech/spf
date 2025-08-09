#pragma once
#include <cstdint>

#include "fft_noreorder.cuh"
#include "fft_f32_impl.cuh"
#include "fft_f64_impl.cuh"
#include "fft_params.cuh"
#include "../math.cuh"

// 20kB is Large enough for 1024 point FFT, but small enough to schedule 2 thread blocks 
// per SM.
const size_t FFT_BUFFER_SIZE = 20 * 1024;
__shared__ uint8_t FFT_BUFFER[FFT_BUFFER_SIZE];

template<typename T>
__device__ constexpr T* get_fft_scratch() {
    return reinterpret_cast<T *>(FFT_BUFFER);
}

template <typename T>
__device__ void fft(Complex<T> *s_input, uint32_t n)
{
    using VecT = typename Complex<T>::VecT;

    __syncthreads();
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
    __syncthreads();
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
        CT_DIT_FFT_4way<FFT_1024_forward_noreorder>(reinterpret_cast<VecT*>(s_input));
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
        CT_DIF_FFT_4way<FFT_1024_inverse_noreorder>(reinterpret_cast<VecT*>(s_input));
        break;
    default:
        printf("Illegal FFT size %d", n);
        assert(false);
    }

    __syncthreads();
}