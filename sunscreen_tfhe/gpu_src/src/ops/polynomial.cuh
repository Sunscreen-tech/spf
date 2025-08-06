#pragma once

#include "../iter_tools.cuh"
#include "../entities/polynomial.cuh"

template <typename T>
__device__ inline void polynomial_sub(
    Polynomial<T> *c,
    const Polynomial<T> *a,
    const Polynomial<T> *b,
    const PolynomialDegree params)
{
    BLOCK_FOR_EACH(i, params.degree)
    {
        c->coeffs()[i] = a->coeffs()[i] - b->coeffs()[i];
    }
}