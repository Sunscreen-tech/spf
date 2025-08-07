#pragma once

#include <cstdint>

#include "polynomial.cuh"
#include "../entities/scratch.cuh"
#include "../entities/glwe.cuh"
#include "../entities/glev.cuh"
#include "../math/signed_decomposer.cuh"
#include "../params.cuh"

template <typename T>
__device__ inline void glwe_sub(
    GlweCiphertext<T> *__restrict__ c,
    const GlweCiphertext<T> *a,
    const GlweCiphertext<T> *b,
    const GlweDef &params)
{
    // Add the `a` terms
    for (uint32_t i = 0; i < params.size.val; i++)
    {
        auto c_a_i = c->a_b(i, params);
        auto a_a_i = a->a_b(i, params);
        auto b_a_i = b->a_b(i, params);

        polynomial_sub(c_a_i, a_a_i, b_a_i, params.polynomial_degree());
    }

    // Add `b`
    auto c_b = c->a_b(params.size.val, params);
    auto a_b = a->a_b(params.size.val, params);
    auto b_b = b->a_b(params.size.val, params);

    polynomial_sub(c_b, a_b, b_b, params.polynomial_degree());
}

template <typename T>
__device__ inline void glwe_add(
    GlweCiphertext<T> *__restrict__ c,
    const GlweCiphertext<T> *a,
    const GlweCiphertext<T> *b,
    const GlweDef &params)
{
    // Add the `a` terms
    for (uint32_t i = 0; i < params.size.val; i++)
    {
        auto c_a_i = c->a_b(i, params);
        auto a_a_i = a->a_b(i, params);
        auto b_a_i = b->a_b(i, params);

        polynomial_add(c_a_i, a_a_i, b_a_i, params.polynomial_degree());
    }

    // Add `b`
    auto c_b = c->a_b(params.size.val, params);
    auto a_b = a->a_b(params.size.val, params);
    auto b_b = b->a_b(params.size.val, params);

    polynomial_add(c_b, a_b, b_b, params.polynomial_degree());
}

template <typename T>
__device__ inline void glwe_polynomial_mad(
    GlweCiphertextFft<T> *__restrict__ c,
    const GlweCiphertextFft<T> *__restrict__ a,
    const PolynomialFft<T> *__restrict__ b,
    const GlweDef &params)
{
    // Multiply-add the
    for (uint32_t i = 0; i < params.size.val; i++)
    {
        auto a_i = a->a_b(i, params);
        auto c_i = c->a_b(i, params);

        polynomial_mad<T>(c_i, a_i, b, params.polynomial_degree());
    }

    auto a_b = a->a_b(params.size.val, params);
    auto c_b = c->a_b(params.size.val, params);


    polynomial_mad<T>(c_b, a_b, b, params.polynomial_degree());
}

template <typename T, typename U>
__device__ inline void decomposed_polynomial_glev_mad(
    GlweCiphertextFft<U> *__restrict__ c,
    const Polynomial<T> *__restrict__ a,
    const GlevCiphertextFft<U> *__restrict__ b,
    const GlweDef &glwe,
    const RadixDecomposition &radix,
    PerBlockStackAllocator &scratch)
{
    auto decomp_scratch = scratch.alloc<Polynomial<T>>(glwe.polynomial_degree());
    auto decomp = PolynomialSignedRadixDecomposer<T>(a, *decomp_scratch, radix, glwe.polynomial_degree());

    auto decomp_poly = get_fft_scratch<Polynomial<uint64_t>>();

    for (uint32_t i = 0; i < radix.count.val; i++)
    {
        uint32_t l = radix.count.val - i - 1;

        auto b_l = b->decomps(l, std::tuple(glwe, radix));
        decomp.next(decomp_poly);

        auto decomp_poly_fft = decomp_poly->fft_inplace<Complex<double>>(glwe.polynomial_degree());

        glwe_polynomial_mad(c, b_l, decomp_poly_fft, glwe);
    }
}