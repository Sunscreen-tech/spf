#pragma once
#include <cstdint>

struct PolynomialDegree
{
    uint32_t degree;

    __device__ inline PolynomialDegree(uint32_t degree) : degree(degree) {}
};

class LweDef
{
public:
    uint32_t size;
};

class GlweDef
{
public:
    uint32_t log_polynomial_degree;
    uint32_t size;

    __device__ inline PolynomialDegree polynomial_degree() const
    {
        return PolynomialDegree(1 << log_polynomial_degree);
    }
};

struct RadixDecomposition
{
    uint32_t count;
    uint32_t radix_log;

    __device__ inline RadixDecomposition(uint32_t count, uint32_t radix_log) : count(count), radix_log(radix_log) {}
};
