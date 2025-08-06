#pragma once

#include <cstdint>

#include "polynomial.cuh"
#include "../entities/glwe.cuh"
#include "../params.cuh"

template <typename T>
__device__ inline void glwe_sub(
    GlweCiphertext<T> *c,
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
    GlweCiphertext<T> *c,
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