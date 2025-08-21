#pragma once

#include "../iter_tools.cuh"
#include "../entities/polynomial.cuh"

__device__ inline void polynomial_sub(
    Polynomial c,
    const Polynomial a,
    const Polynomial b,
    const PolynomialDegree params)
{
    BLOCK_FOR_EACH(i, params.val)
    {
        auto val = a.coeffs().get_u64(i) - b.coeffs().get_u64(i);
        c.coeffs().set_u64(i, val);
    }
}

__device__ inline void polynomial_add(
    Polynomial c,
    const Polynomial a,
    const Polynomial b,
    const PolynomialDegree params)
{
    BLOCK_FOR_EACH(i, params.val)
    {
        auto val = a.coeffs().get_u64(i) - b.coeffs().get_u64(i);
        c.coeffs().set_u64(i, val);
    }
}

__device__ inline void polynomial_mad(
    PolynomialFft c,
    const PolynomialFft a,
    const PolynomialFft b,
    const PolynomialDegree params)
{
    // FFT'd polynomials are half length.
    BLOCK_FOR_EACH(i, params.val / 2)
    {
        c.coeffs().as_complex()[i] = a.coeffs().as_complex()[i] * b.coeffs().as_complex()[i] + c.coeffs().as_complex()[i];
    }
}