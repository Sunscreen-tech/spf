#pragma once
#include <cstdint>

#include "twiddles.cuh"
#include "../math.cuh"
#include "./fft.cuh"
#include "../../iter_tools.cuh"

template <typename T>
__device__ inline Complex<T>* apply_twist(
    T* s_input,
    uint32_t n
) {
    static_assert(2 * sizeof(T) == sizeof(Complex<T>));
    
    uint32_t n_times_2 = n * 2;
    uint32_t n_div_2 = n / 2;
    auto s_output = reinterpret_cast<Complex<T>*>(s_input);

    uint32_t tid = threadIdx.x;
    uint32_t dim = blockDim.x;

    
    printf("%d/%d\n", tid, dim);

    // Since negacyclic FFT requires n / 8 threads in a block, we have each thread load their values 
    // into registers so we can write them back to shared memory in a coordinated manner.
    //
    // Our input is over T, but we're emitting an output over Complex<T>. As such, each thread needs to
    // produce 4 complex points (which consumes 8 values in the original input array).
    auto c0 = Complex<T>(s_input[tid + 0 * dim], s_input[tid + n_div_2 + 0 * dim]);
    auto c1 = Complex<T>(s_input[tid + 1 * dim], s_input[tid + n_div_2 + 1 * dim]);
    auto c2 = Complex<T>(s_input[tid + 2 * dim], s_input[tid + n_div_2 + 2 * dim]);
    auto c3 = Complex<T>(s_input[tid + 3 * dim], s_input[tid + n_div_2 + 3 * dim]);
    
    // Ensure all our values have been loaded into registers.
    __syncthreads();

    // Now write our complex registers back to shared memory.
    s_output[tid + 0 * dim] = c0 * FftTwiddles<T>::Get_W_value_inverse(n_times_2, tid + 0 * dim);
    s_output[tid + 1 * dim] = c1 * FftTwiddles<T>::Get_W_value_inverse(n_times_2, tid + 1 * dim);
    s_output[tid + 2 * dim] = c2 * FftTwiddles<T>::Get_W_value_inverse(n_times_2, tid + 2 * dim);
    s_output[tid + 3 * dim] = c3 * FftTwiddles<T>::Get_W_value_inverse(n_times_2, tid + 3 * dim);

    __syncthreads();

    return s_output;
}

template <typename T>
__device__ inline T* remove_twist(
    Complex<T>* s_input,
    uint32_t n
) {
    static_assert(2 * sizeof(T) == sizeof(Complex<T>));

    uint32_t n_times_2 = n * 2;
    uint32_t n_div_2 = n / 2;
    T n_inv = 1.0 / (T)n_div_2;

    auto s_output = reinterpret_cast<T*>(s_input);

    uint32_t tid = threadIdx.x;
    uint32_t dim = blockDim.x;

    // As with twisting, we load 4 Complex values into registers and then synchronize so we can overwrite our input buffer.
    auto c0 = s_input[tid + 0 * dim] * FftTwiddles<T>::Get_W_value(n_times_2, tid + 0 * dim) * n_inv;
    auto c1 = s_input[tid + 1 * dim] * FftTwiddles<T>::Get_W_value(n_times_2, tid + 1 * dim) * n_inv;
    auto c2 = s_input[tid + 2 * dim] * FftTwiddles<T>::Get_W_value(n_times_2, tid + 2 * dim) * n_inv;
    auto c3 = s_input[tid + 3 * dim] * FftTwiddles<T>::Get_W_value(n_times_2, tid + 3 * dim) * n_inv;

    __syncthreads();

    s_output[tid + 0 * dim] = round(c0.re());
    s_output[tid + 0 * dim + n_div_2] = round(c0.im());
    s_output[tid + 1 * dim] = round(c1.re());
    s_output[tid + 1 * dim + n_div_2] = round(c1.im());
    s_output[tid + 2 * dim] = round(c2.re());
    s_output[tid + 2 * dim + n_div_2] = round(c2.im());
    s_output[tid + 3 * dim] = round(c3.re());
    s_output[tid + 3 * dim + n_div_2] = round(c3.im());

    __syncthreads();

    return s_output;
}

/// Compute a forward FFT over real negacyclic input `s_input`.
template <typename T>
__device__ Complex<T>* twisted_fft(
    T *s_input,
    uint32_t n)
{
    uint32_t n_div_2 = n / 2;
    T n_inv = 1.0 / (T)n_div_2;

    auto s_output = apply_twist(s_input, n);

    __syncthreads();

    // Perform an n/2 FFT.
    fft(s_output, n_div_2);

    return s_output;
}

/// Compute a twisted IFFT resulting in real negacyclic output `s_output`.
/// This result is still in floating point and needs to be modulo reduced.
template <typename T>
__device__ T* twisted_ifft(
    Complex<T> *s_input,
    uint32_t n)
{
    uint32_t n_div_2 = n / 2;

    // Perform an n/2 IFFT.
    ifft(s_input, n_div_2);

    return remove_twist(s_input, n);
}

/// Compute a forward in-place FFT over real negacyclic input `s_input`. For best performance,
/// s_input should be shared memory.
///
/// The returned pointer is the input buffer re-interpreted as `Complex<T>`
template <typename T>
__device__ Complex<T>* twisted_fft_noreorder(
    T *s_input,
    uint32_t n)
{
    uint32_t n_div_2 = n / Float<T>::TWO;

    auto s_output = apply_twist(s_input, n);

    // Perform an n/2 FFT.
    fft_noreorder(s_output, n_div_2);

    return s_output;
}

/// Compute a twisted IFFT resulting in real negacyclic output `s_output`.
/// This result is still in floating point and needs to be modulo reduced.
template <typename T>
__device__ T* twisted_ifft_noreorder(
    Complex<T> *s_input,
    uint32_t n)
{
    uint32_t n_div_2 = n / 2;

    // Perform an n/2 IFFT.
    ifft_noreorder(s_input, n_div_2);

    return remove_twist(s_input, n);
}
