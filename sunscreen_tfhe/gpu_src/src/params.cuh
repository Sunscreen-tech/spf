#pragma once
#include <cstdint>

struct LogPolyDegree
{
public:
    __device__ LogPolyDegree() = delete;
    __device__ constexpr inline LogPolyDegree(uint32_t log_poly_degree) : val(log_poly_degree) {}

    uint32_t val;
};

struct GlweSize
{
public:
    __device__ GlweSize() = delete;
    __device__ constexpr inline GlweSize(uint32_t glwe_size) : val(glwe_size) {}

    uint32_t val;
};

struct PolynomialDegree
{
    uint32_t val;

    __device__ constexpr inline PolynomialDegree(uint32_t degree) : val(degree) {}
};

class LweDef
{
public:
    uint32_t size;
};

class GlweDef
{
public:
    __device__ GlweDef() = delete;
    __device__ constexpr inline GlweDef(LogPolyDegree log_poly_degree, GlweSize size) : log_poly_degree(log_poly_degree), size(size) {}

    LogPolyDegree log_poly_degree;
    GlweSize size;

    __device__ inline PolynomialDegree polynomial_degree() const
    {
        return PolynomialDegree(1 << log_poly_degree.val);
    }
};

struct RadixCount
{
public:
    __device__ RadixCount() = delete;
    __device__ constexpr inline RadixCount(uint32_t count) : val(count) {}

    uint32_t val;
};

struct RadixLog
{
public:
    __device__ RadixLog() = delete;
    __device__ constexpr inline RadixLog(uint32_t log) : val(log) {}

    uint32_t val;
};

struct RadixDecomposition
{
    RadixCount count;
    RadixLog radix_log;

    __device__ RadixDecomposition() = delete;
    __device__ constexpr inline RadixDecomposition(RadixCount count, RadixLog radix_log) : count(count), radix_log(radix_log) {}
};

__device__ const RadixDecomposition PBS_RADIX_128 = RadixDecomposition(RadixCount(2), RadixLog(16));
__device__ const GlweDef GLWE_1_128 = GlweDef(LogPolyDegree(11), GlweSize(1));