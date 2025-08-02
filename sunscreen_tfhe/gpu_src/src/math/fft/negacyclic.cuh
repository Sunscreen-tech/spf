#pragma once
#include <cstdint>

#include "twiddles.cuh"
#include "../math.cuh"
#include "./fft.cuh"

/// Compute a forward FFT over real negacyclic input `s_input`.
template <typename T>
__device__ void twisted_fft(
    const T * __restrict__ s_input,
    Complex<T> * __restrict__ s_output,
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
    Complex<T> * __restrict__ s_input,
    T * __restrict__ s_output,
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
template <typename Complex>
__device__ void twisted_fft_noreorder(
    const typename ScalarOf<Complex>::Ty * __restrict__ s_input,
    Complex * __restrict__ s_output,
    uint32_t n)
{
    using S = ScalarOf<Complex>;
    uint32_t n_div_2 = n / Float<S>::TWO;

    // Split the input into 2 sub arrays, packing the first half into the real
    // component of our twist and the second half into the imaginary part.
    // Then, multiply by out twist factor.
    for (uint32_t i = threadIdx.x; i < n; i += blockDim.x)
    {
        s_output[i] = complex_mul({(S)s_input[i], (S)s_input[i + n_div_2]}, twist(i));
    }

    // Perform an n/2 FFT.
    fft_noreorder(s_input, n_div_2);

    __syncthreads();
}

/// Compute a twisted IFFT resulting in real negacyclic output `s_output`.
/// This result is still in floating point and needs to be modulo reduced.
template <typename Complex>
__device__ void twisted_ifft_noreorder(
    const Complex * __restrict__ s_input,
    typename ScalarOf<Complex>::Ty * __restrict__ s_output,
    uint32_t n)
{
    using S = ScalarOf<Complex>::Ty;
    uint32_t n_div_2 = n / 2;

    // Perform an n/2 IFFT.
    ifft_noreorder(s_input, n_div_2);

    __syncthreads();

    S n_inv = Float<S>::TWO / (S)n;

    // Twist the inputs so we can use an N-point FFT for negacyclic
    // convolution
    for (uint32_t i = threadIdx.x; i < n; i += blockDim.x)
    {
        Complex tmp = complex_mul(s_input[i], twist_inv(i));
        tmp = complex_mul_real(tmp, n_inv);

        s_output[i] = tmp.x.round();
        s_output[i + n_div_2] = tmp.y.round();
    }
}

template <typename Complex, uint64_t LOG2_Q>
__device__ void q_as_float();

template <uint64_t LOG2_Q>
__device__ inline typename ScalarOf<float2>::Ty q_as_float<float2>() {
    uint64_t exp = 127 + LOG2_Q;

    return reinterpret_cast<ScalarOf<double2>::Ty>(exp << 23);
}

template <uint64_t LOG2_Q>
__device__ inline typename ScalarOf<double2>::Ty q_as_float<double2>() {
    uint64_t exp = 1023 + LOG2_Q;

    return reinterpret_cast<ScalarOf<double2>::Ty>(exp << 52);
}

/// Reduce each value in `s_input` by `2**LOG2_Q` and emit the results as `uint64_t`s.
template <typename Complex, uint64_t LOG2_Q>
__device__ void reduce_mod_q_pow_2(
    typename ScalarOf<Complex>::Ty * __restrict__ s_input,
    uint64_t * __restrict__ output,
    uint32_t n)
{
    using S = ScalarOf<Complex>::Ty;

    S q = q_as_float<LOG2_Q>();
    S q_div2 = q_as_float<LOG2_Q - 1>();

    for (uint32_t i = threadIdx.x; i < n; i += blockDim.x) {
        S val = s_input[i];

        // Reduce mod_q, exploiting the fact that q is a power of 2.
        S rem = -(val / q).trunc() * q + val;

        // Normalize results outsize [-q/2, q/2) to be within the torus.
        // Pretty please emit conditional movs to avoid branch divergence :)
        S rem_min_q = rem - q;
        S rem_plus_q = rem + q;

        rem = rem >= q_div2
            ? rem_min_q
            : rem;

        rem = rem < -q_div2
            ? rem_plus_q
            : rem;

        output[i] = rem;
    }
}