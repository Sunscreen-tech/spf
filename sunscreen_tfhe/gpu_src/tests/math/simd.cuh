#pragma once
#include <cuda/std/complex>
#include <cstdint>

#include "../../src/iter_tools.cuh"
#include "../../src/math/simd.cuh"
#include "../../src/ops/polynomial.cuh"

extern "C" __global__ void can_reduce_mod_2_pow_64(
    double *__restrict__ input,
    uint64_t *__restrict__ output,
    const u32 n)
{
    inplace_reduce_mod_q_pow_2<double, 64>(input, n);

    BLOCK_FOR_EACH(i, n)
    {
        output[i] = signed_to_unsigned_torus<double, uint64_t>(input[i]);
    }
}

extern "C" __global__ void can_complex_mad(
    cuda::std::complex<f64> *__restrict__ c_buf,
    const cuda::std::complex<f64> *__restrict__ a_buf,
    const cuda::std::complex<f64> *__restrict__ b_buf,
    const u32 n)
{
    auto degree = PolynomialDegree(2 * n);

    // Just make a big old buffer out of a polynomial
    auto c = PolynomialFft::from_ptr(c_buf);
    auto a = PolynomialFft::from_ptr(a_buf);
    auto b = PolynomialFft::from_ptr(b_buf);

    polynomial_mad(c, a, b, degree);
}