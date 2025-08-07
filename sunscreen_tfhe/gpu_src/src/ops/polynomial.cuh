#pragma once

#include "../iter_tools.cuh"
#include "../entities/polynomial.cuh"

template <typename T>
__device__ inline void polynomial_sub(
    Polynomial<T> *__restrict__ c,
    const Polynomial<T> *a,
    const Polynomial<T> *b,
    const PolynomialDegree params)
{
    BLOCK_FOR_EACH(i, params.val)
    {
        c->coeffs()[i] = a->coeffs()[i] - b->coeffs()[i];
    }
}

template <typename T>
__device__ inline void polynomial_add(
    Polynomial<T> *__restrict__ c,
    const Polynomial<T> *a,
    const Polynomial<T> *b,
    const PolynomialDegree params)
{
    BLOCK_FOR_EACH(i, params.val)
    {
        c->coeffs()[i] = a->coeffs()[i] + b->coeffs()[i];
    }
}

template <typename T>
__device__ inline void polynomial_mad(
    PolynomialFft<T> *__restrict__ c,
    const PolynomialFft<T> *a,
    const PolynomialFft<T> *b,
    const PolynomialDegree params
) {
    BLOCK_FOR_EACH(i, params.val)
    {
        c->coeffs()[i] = a->coeffs()[i] * b->coeffs()[i] + c->coeffs()[i];
    }
}