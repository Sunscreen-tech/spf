#pragma once
#include <cstdint>
#include "../../src/entities/polynomial.cuh"
#include "../../src/iter_tools.cuh"

extern "C" __global__ void can_allocate_and_use_scratch(
    const Polynomial<uint64_t> *__restrict__ x,
    Polynomial<uint64_t> *__restrict__ y,
    const uint32_t n)
{
    init_scratch();
    const PolynomialDegree degree = PolynomialDegree{n};
    auto tmp = scratch_alloc<Polynomial<uint64_t>>(degree);

    BLOCK_FOR_EACH(i, n)
    {
        tmp->coeffs()[i] = x->coeffs()[i];
    }

    BLOCK_FOR_EACH(i, n)
    {
        y->coeffs()[i] = tmp->coeffs()[i];
    }
}