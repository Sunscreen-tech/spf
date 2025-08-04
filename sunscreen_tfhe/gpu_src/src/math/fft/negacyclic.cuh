#pragma once
#include <cstdint>

#include "twiddles.cuh"
#include "../math.cuh"
#include "./fft.cuh"
#include "../../iter_tools.cuh"

/// Compute a forward FFT over real negacyclic input `s_input`.
template <typename T>
__device__ void twisted_fft(
    const T *__restrict__ s_input,
    Complex<T> *__restrict__ s_output,
    uint32_t n)
{
    uint32_t n_div_2 = n / 2;

    // Split the input into 2 sub arrays, packing the first half into the real
    // component of our twist and the second half into the imaginary part.
    // Then, multiply by out twist factor.
    for (uint32_t i = threadIdx.x; i < n_div_2; i += blockDim.x)
    {
        Complex<T> c({s_input[i], s_input[i + n_div_2]});
        Complex<T> twist(FftTwiddles<T>::Get_W_value_inverse(2 * n, i));

        s_output[i] = c * twist;
    }

    __syncthreads();

    // Perform an n/2 FFT.
    fft(s_output, n_div_2);
}

/// Compute a twisted IFFT resulting in real negacyclic output `s_output`.
/// This result is still in floating point and needs to be modulo reduced.
template <typename T>
__device__ void twisted_ifft(
    Complex<T> *__restrict__ s_input,
    T *__restrict__ s_output,
    uint32_t n)
{
    uint32_t n_div_2 = n / 2;

    // Perform an n/2 IFFT.
    ifft(s_input, n_div_2);

    T n_inv = 1.0 / (T)n_div_2;

    // Twist the inputs so we can use an N-point FFT for negacyclic
    // convolution
    for (uint32_t i = threadIdx.x; i < n_div_2; i += blockDim.x)
    {
        Complex<T> twist_inv(FftTwiddles<T>::Get_W_value(2 * n, i));
        Complex tmp = s_input[i] * twist_inv * n_inv;

        s_output[i] = round(tmp.re());
        s_output[i + n_div_2] = round(tmp.im());
    }

    __syncthreads();
}

/// Compute a forward FFT over real negacyclic input `s_input`.
template <typename T>
__device__ void twisted_fft_noreorder(
    const T *__restrict__ s_input,
    Complex<T> *__restrict__ s_output,
    uint32_t n)
{
    uint32_t n_div_2 = n / Float<T>::TWO;

    // Split the input into 2 sub arrays, packing the first half into the real
    // component of our twist and the second half into the imaginary part.
    // Then, multiply by out twist factor.
    for (uint32_t i = threadIdx.x; i < n; i += blockDim.x)
    {
        s_output[i] = complex_mul({s_input[i], s_input[i + n_div_2]}, FftTwiddles<T>::Get_W_value_inverse(2 * n, i));
    }

    __syncthreads();

    // Perform an n/2 FFT.
    fft_noreorder(s_output, n_div_2);
}

/// Compute a twisted IFFT resulting in real negacyclic output `s_output`.
/// This result is still in floating point and needs to be modulo reduced.
template <typename T>
__device__ void twisted_ifft_noreorder(
    Complex<T> *__restrict__ s_input,
    T *__restrict__ s_output,
    uint32_t n)
{
    uint32_t n_div_2 = n / 2;

    // Perform an n/2 IFFT.
    ifft_noreorder(s_input, n_div_2);

    __syncthreads();

    T n_inv = Float<T>::TWO / (T)n;

    // Twist the inputs so we can use an N-point FFT for negacyclic
    // convolution
    for (uint32_t i = threadIdx.x; i < n; i += blockDim.x)
    {
        Complex<T> twist_inv(FftTwiddles<T>::Get_W_value(2 * n, i));
        Complex<T> tmp = s_input[i] * twist_inv * n_inv;

        s_output[i] = round(tmp.re());
        s_output[i + n_div_2] = round(tmp.im());
    }

    __syncthreads();
}
