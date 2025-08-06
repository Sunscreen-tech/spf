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
    for (uint32_t i = 0; i < params.size; i++)
    {
        auto c_a_i = c->a_b(i, params);
        auto a_a_i = c->a_b(i, params);
        auto b_a_i = c->a_b(i, params);

        polynomial_sub(c_a_i, a_a_i, b_a_i);
    }

    // Add `b`
    auto c_b = c->a_b(i, params);
    auto a_b = c->a_b(i, params);
    auto b_b = c->a_b(i, params);

    polynomial_sub(c_b, a_b, b_b);
}