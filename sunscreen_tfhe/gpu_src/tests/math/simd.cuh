#pragma once
#include <cstdint>

#include "../../src/iter_tools.cuh"
#include "../../src/math/simd.cuh"
#include "../../src/ops/polynomial.cuh"

extern "C" __global__ void can_reduce_mod_2_pow_64(
    double *__restrict__ input,
    uint64_t *__restrict__ output,
    const uint32_t n)
{
    inplace_reduce_mod_q_pow_2<double, 64>(input, n);

    BLOCK_FOR_EACH(i, n)
    {
        output[i] = signed_to_unsigned_torus<double, uint64_t>(input[i]);
    }
}

extern "C" __global__ void can_complex_mad(
    PolynomialFft<Complex<double>> *__restrict__ c,
    const PolynomialFft<Complex<double>> *__restrict__ a,
    const PolynomialFft<Complex<double>> *__restrict__ b,
    const uint32_t n)
{
    auto degree = PolynomialDegree(2 * n);

    polynomial_mad(c, a, b, degree);
}