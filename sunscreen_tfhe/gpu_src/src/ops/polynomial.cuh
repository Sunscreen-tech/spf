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
        auto val = a.coeffs().get_u64(i) + b.coeffs().get_u64(i);
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
        auto c_i = c.coeffs().as_complex()[i];
        auto a_i = a.coeffs().as_complex()[i];
        auto b_i = b.coeffs().as_complex()[i];
        double2 result;

        result.x = fma(a_i.real(), b_i.real(), c_i.real());
        result.y = fma(a_i.real(), b_i.imag(), c_i.imag());
        result.x = fma(-a_i.imag(), b_i.imag(), result.x);
        result.y = fma(a_i.imag(), b_i.real(), result.y);
        
        c.coeffs().as_complex()[i] = cuda::std::complex(result.x, result.y);
    }
}