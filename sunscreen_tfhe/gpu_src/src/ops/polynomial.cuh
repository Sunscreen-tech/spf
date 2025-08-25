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

__device__ inline void polynomial_sub_assign(
    Polynomial c,
    const Polynomial a,
    const PolynomialDegree params
) {
    BLOCK_FOR_EACH(i, params.val)
    {
        auto val = c.coeffs().get_u64(i) - a.coeffs().get_u64(i);
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

__device__ inline void polynomial_times_negative_monomial_negacyclic(
    Polynomial out,
    const Polynomial in,
    const u32 rotation,
    const PolynomialDegree degree
) {
    BLOCK_FOR_EACH(i, degree.val) {
        auto val = in.get_i64(i);
        auto out_loc = i + rotation;

        if (out_loc > degree.val) {
            val = -val;
            out_loc -= degree.val;
        }

        out.set_i64(out_loc, val);
    }
}

__device__ inline void polynomial_times_positive_monomial_negacyclic(
    Polynomial out,
    const Polynomial in,
    const u32 rotation,
    const PolynomialDegree degree
) {
    BLOCK_FOR_EACH(i, degree.val) {
        auto val = in.get_i64(i);
        u32 out_loc

        if (i < rotation) {
            val = -val;
            out_loc = degree.val - rotation + i;
        } else {
            out_loc = i - rotation;
        }

        out.set_i64(out_loc, val);
    }
}