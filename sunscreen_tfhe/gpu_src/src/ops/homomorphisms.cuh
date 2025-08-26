#pragma once

#include <cstdint>

#include "polynomial.cuh"
#include "../entities/scratch.cuh"
#include "../entities/glwe.cuh"
#include "../entities/glev.cuh"
#include "../entities/ggsw.cuh"
#include "../math/signed_decomposer.cuh"
#include "../params.cuh"

__device__ inline void glwe_sub(
    GlweCiphertext c,
    const GlweCiphertext a,
    const GlweCiphertext b,
    const GlweDef &params)
{
    // Sub the `a` terms
    for (u32 i = 0; i < params.size.val; i++)
    {
        auto c_a_i = c.a_b(i, params);
        auto a_a_i = a.a_b(i, params);
        auto b_a_i = b.a_b(i, params);

        polynomial_sub(c_a_i, a_a_i, b_a_i, params.polynomial_degree());
    }

    // Sub `b`
    auto c_b = c.a_b(params.size.val, params);
    auto a_b = a.a_b(params.size.val, params);
    auto b_b = b.a_b(params.size.val, params);

    polynomial_sub(c_b, a_b, b_b, params.polynomial_degree());
}

__device__ inline void glwe_add(
    GlweCiphertext c,
    const GlweCiphertext a,
    const GlweCiphertext b,
    const GlweDef &params)
{
    // Add the `a` terms
    for (u32 i = 0; i < params.size.val; i++)
    {
        auto c_a_i = c.a_b(i, params);
        auto a_a_i = a.a_b(i, params);
        auto b_a_i = b.a_b(i, params);

        polynomial_add(c_a_i, a_a_i, b_a_i, params.polynomial_degree());
    }

    // Add `b`
    auto c_b = c.a_b(params.size.val, params);
    auto a_b = a.a_b(params.size.val, params);
    auto b_b = b.a_b(params.size.val, params);

    polynomial_add(c_b, a_b, b_b, params.polynomial_degree());
}

__device__ inline void glwe_polynomial_mad(
    GlweCiphertextFft c,
    const GlweCiphertextFft a,
    const PolynomialFft b,
    const GlweDef &params)
{
    // Multiply-add the
    for (u32 i = 0; i < params.size.val; i++)
    {
        auto a_i = a.a_b(i, params);
        auto c_i = c.a_b(i, params);

        polynomial_mad(c_i, a_i, b, params.polynomial_degree());
    }

    auto a_b = a.a_b(params.size.val, params);
    auto c_b = c.a_b(params.size.val, params);

    polynomial_mad(c_b, a_b, b, params.polynomial_degree());
}

__device__ inline void decomposed_polynomial_glev_mad(
    GlweCiphertextFft c,
    const Polynomial a,
    const GlevCiphertextFft b,
    const GlweDef &glwe,
    const RadixDecomposition &radix,
    PerBlockStackAllocator &scratch)
{
    // Under standard parameters, we allocate another 32kB of memory.
    auto decomp_scratch = scratch.alloc<Polynomial>(glwe.polynomial_degree());
    auto decomp = PolynomialSignedRadixDecomposer(a, *decomp_scratch, radix, glwe.polynomial_degree());
    auto decomp_poly = scratch.alloc<Polynomial>(glwe.polynomial_degree());

    for (u32 i = 0; i < radix.count.val; i++)
    {
        u32 l = radix.count.val - i - 1;

        auto b_l = b.decomps(l, std::tuple(glwe, radix));
        decomp.next(*decomp_poly);

        auto decomp_poly_fft = std::move(*decomp_poly).fft_inplace(glwe.polynomial_degree());

        glwe_polynomial_mad(c, b_l, decomp_poly_fft, glwe);
    }
}

__device__ inline void glwe_ggsw_mad(
    GlweCiphertextFft c_fft,
    const GlweCiphertext a,
    const GgswCiphertextFft b,
    const GlweDef &glwe,
    const RadixDecomposition &radix,
    PerBlockStackAllocator &scratch)
{
    for (u32 i = 0; i < glwe.size.val; i++)
    {
        auto a_i = a.a_b(i, glwe);
        auto glev_i = b.rows(i, std::tuple(glwe, radix));

        decomposed_polynomial_glev_mad(c_fft, a_i, glev_i, glwe, radix, scratch);
    }

    auto a_i = a.a_b(glwe.size.val, glwe);
    auto glev_i = b.rows(glwe.size.val, std::tuple(glwe, radix));

    decomposed_polynomial_glev_mad(c_fft, a_i, glev_i, glwe, radix, scratch);
}

__device__ inline void cmux(
    GlweCiphertext c,
    const GlweCiphertext a,
    const GlweCiphertext b,
    const GgswCiphertextFft sel,
    const GlweDef &glwe,
    const RadixDecomposition &radix,
    PerBlockStackAllocator &scratch)
{
    auto diff = scratch.alloc<GlweCiphertext>(glwe);

    glwe_sub(*diff, b, a, glwe);

    auto prod_fft = scratch.alloc<GlweCiphertextFft>(glwe);
    prod_fft.clear();

    glwe_ggsw_mad(*prod_fft, *diff, sel, glwe, radix, scratch);

    auto prod = scratch.alloc<GlweCiphertext>(glwe);

    (*prod_fft).ifft(*prod, glwe);

    glwe_add(c, *prod, a, glwe);
}

/// @brief Computes c -= a
__device__ inline void glwe_sub_assign(
    GlweCiphertext c,
    GlweCiphertext a,
    const GlweDef &params
 ) {
    // Sub the `a` terms
    for (u32 i = 0; i < params.size.val; i++)
    {
        auto c_a_i = c.a_b(i, params);
        auto a_a_i = a.a_b(i, params);

        polynomial_sub_assign(c_a_i, a_a_i, params.polynomial_degree());
    }

    // Sub `b`
    auto c_b = c.a_b(params.size.val, params);
    auto a_b = a.a_b(params.size.val, params);

    polynomial_sub_assign(c_b, a_b, params.polynomial_degree());
}

/// @brief Same a cmux, but more memory efficient. inputs a and b are overwritten
/// and the result is returned in a. Upon return, b contains b - a, as a side 
/// effect, not that this is usually useful.
__device__ inline void destructive_cmux(
    GlweCiphertext a,
    GlweCiphertext b,
    const GgswCiphertextFft sel,
    const GlweDef &glwe,
    const RadixDecomposition &radix,
    PerBlockStackAllocator &scratch)
{
    // b -= a
    glwe_sub_assign(b, a, glwe);

    auto a_fft = std::move(a).fft_inplace(glwe);

    // a += (b - a) * sel
    glwe_ggsw_mad(a_fft, b, sel, glwe, radix, scratch);

    std::move(a_fft).ifft_inplace(glwe);
}


__device__ inline void glwe_times_negative_monomial_negacyclic(
    GlweCiphertext out,
    const GlweCiphertext in,
    const u32 rotation,
    const GlweDef &params
) {
    // Do all a's and b. Hence <=
    for (u32 i = 0; i <= params.size.val; i++) {
        auto out_i = out.a_b(i, params);
        auto in_i = in.a_b(i, params);

        polynomial_times_negative_monomial_negacyclic(out_i, in_i, rotation, params.polynomial_degree());
    }
}

__device__ inline void glwe_times_positive_monomial_negacyclic(
    GlweCiphertext out,
    const GlweCiphertext in,
    const u32 rotation,
    const GlweDef &params
) {
    // Do all a's and b. Hence <=
    for (u32 i = 0; i <= params.size.val; i++) {
        auto out_i = out.a_b(i, params);
        auto in_i = in.a_b(i, params);

        polynomial_times_positive_monomial_negacyclic(out_i, in_i, rotation, params.polynomial_degree());
    }
}