#pragma once

struct LogPolyDegree
{
public:
    __device__ LogPolyDegree() = delete;
    __device__ constexpr inline LogPolyDegree(u32 log_poly_degree) : val(log_poly_degree) {}

    u32 val;
};

struct GlweSize
{
public:
    __device__ GlweSize() = delete;
    __device__ constexpr inline GlweSize(u32 glwe_size) : val(glwe_size) {}

    u32 val;
};

struct PolynomialDegree
{
    u32 val;

    __device__ constexpr inline PolynomialDegree(u32 degree) : val(degree) {}
};

struct LweSize
{
    u32 val;

    __device__ constexpr inline LweSize(u32 size) : val(size) {}
};

class LweDef
{
public:
    __device__ LweDef() = delete;
    __device__ constexpr inline LweDef(LweSize size): size(size) {}

    LweSize size;
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
    __device__ constexpr inline RadixCount(u32 count) : val(count) {}

    u32 val;
};

struct RadixLog
{
public:
    __device__ RadixLog() = delete;
    __device__ constexpr inline RadixLog(u32 log) : val(log) {}

    u32 val;
};

struct RadixDecomposition
{
    RadixCount count;
    RadixLog radix_log;

    __device__ RadixDecomposition() = delete;
    __device__ constexpr inline RadixDecomposition(RadixCount count, RadixLog radix_log) : count(count), radix_log(radix_log) {}
};

__device__ const RadixDecomposition PBS_RADIX_2_16_128 = RadixDecomposition(RadixCount(2), RadixLog(16));
__device__ const LweDef LWE_637_128 = LweDef(LweSize(637));
__device__ const GlweDef GLWE_1_2048_128 = GlweDef(LogPolyDegree(11), GlweSize(1));