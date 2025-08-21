#pragma once
#include <cuda/std/complex>
#include <cstdint>

#include "twiddles.cuh"
#include "../entities/punbuf.cuh"
#include "../math.cuh"
#include "../primitives.cuh"
#include "./fft.cuh"
#include "../../iter_tools.cuh"

__device__ inline apply_twist(
    PunBuf punbuf,
    u32 n
) {
    static_assert(2 * sizeof(T) == sizeof(Complex<T>));
    
    u32 n_times_2 = n * 2;
    u32 n_div_2 = n / 2;
    u32 tid = threadIdx.x;
    u32 dim = blockDim.x;

    auto as_f64 = punbuf.as_f64();

    // Since negacyclic FFT requires n / 8 threads in a block, we have each thread load their values 
    // into registers so we can write them back to shared memory in a coordinated manner.
    //
    // Our input is over T, but we're emitting an output over Complex<T>. As such, each thread needs to
    // produce 4 complex points (which consumes 8 values in the original input array).
    auto c0 = cuda::std::complex<f64>(as_f64[tid + 0 * dim], as_f64[tid + n_div_2 + 0 * dim]);
    auto c1 = cuda::std::complex<f64>(as_f64[tid + 1 * dim], as_f64[tid + n_div_2 + 1 * dim]);
    auto c2 = cuda::std::complex<f64>(as_f64[tid + 2 * dim], as_f64[tid + n_div_2 + 2 * dim]);
    auto c3 = cuda::std::complex<f64>(as_f64[tid + 3 * dim], as_f64[tid + n_div_2 + 3 * dim]);
    
    // Ensure all our values have been loaded into registers.
    __syncthreads();

    auto as_complex = punbuf.as_complex();

    // Now write our complex registers back to shared memory.
    as_complex[tid + 0 * dim] = c0 * FftTwiddles<T>::Get_W_value_inverse(n_times_2, tid + 0 * dim);
    as_complex[tid + 1 * dim] = c1 * FftTwiddles<T>::Get_W_value_inverse(n_times_2, tid + 1 * dim);
    as_complex[tid + 2 * dim] = c2 * FftTwiddles<T>::Get_W_value_inverse(n_times_2, tid + 2 * dim);
    as_complex[tid + 3 * dim] = c3 * FftTwiddles<T>::Get_W_value_inverse(n_times_2, tid + 3 * dim);

    __syncthreads();
}

__device__ inline T* remove_twist(
    PunBuf punbuf,
    u32 n
) {
    static_assert(2 * sizeof(T) == sizeof(Complex<T>));

    u32 n_times_2 = n * 2;
    u32 n_div_2 = n / 2;
    T n_inv = 1.0 / (T)n_div_2;

    auto as_complex = punbuf.as_complex();

    u32 tid = threadIdx.x;
    u32 dim = blockDim.x;

    // As with twisting, we load 4 Complex values into registers and then synchronize so we can overwrite our input buffer.
    auto c0 = as_complex[tid + 0 * dim] * FftTwiddles<T>::Get_W_value(n_times_2, tid + 0 * dim) * n_inv;
    auto c1 = as_complex[tid + 1 * dim] * FftTwiddles<T>::Get_W_value(n_times_2, tid + 1 * dim) * n_inv;
    auto c2 = as_complex[tid + 2 * dim] * FftTwiddles<T>::Get_W_value(n_times_2, tid + 2 * dim) * n_inv;
    auto c3 = as_complex[tid + 3 * dim] * FftTwiddles<T>::Get_W_value(n_times_2, tid + 3 * dim) * n_inv;

    __syncthreads();

    auto as_f64 = punbuf.as_f64();

    as_f64[tid + 0 * dim] = round(c0.re());
    as_f64[tid + 0 * dim + n_div_2] = round(c0.im());
    as_f64[tid + 1 * dim] = round(c1.re());
    as_f64[tid + 1 * dim + n_div_2] = round(c1.im());
    as_f64[tid + 2 * dim] = round(c2.re());
    as_f64[tid + 2 * dim + n_div_2] = round(c2.im());
    as_f64[tid + 3 * dim] = round(c3.re());
    as_f64[tid + 3 * dim + n_div_2] = round(c3.im());

    __syncthreads();

    return s_output;
}

/// Compute a forward in-place FFT over real negacyclic input `s_input`. For best performance,
/// s_input should be shared memory.
///
/// Upon completion, the complex
__device__ Complex<T>* twisted_fft_noreorder(
    PunBuf s_input,
    u32 n)
{
    u32 n_div_2 = n / Float<T>::TWO;

    auto s_output = apply_twist(s_input, n);

    // Perform an n/2 FFT.
    fft_noreorder(s_output, n_div_2);

    return s_output;
}

/// Compute a twisted IFFT resulting in real negacyclic output `s_output`.
/// This result is still in floating point and needs to be modulo reduced.
template <typename T>
__device__ T* twisted_ifft_noreorder(
    PunBuf s_input,
    u32 n)
{
    u32 n_div_2 = n / 2;

    // Perform an n/2 IFFT.
    ifft_noreorder(s_input, n_div_2);

    return remove_twist(s_input, n);
}
