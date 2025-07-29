#pragma once

const double PI = 3.14159265358979323846264338327950288;
const double TAU = PI * 2.0;

const float PI_F = 3.14159265358979323846264338327950288f;
const float TAU_F = PI * 2.0f;

/// @brief Wraps built-in float types to generalize constants and functions.
/// @tparam S
template <typename S>
class Float
{
};

template <>
class Float<float>
{
public:
    using Ty = float;

    const static Ty TAU = TAU_F;
    const static Ty PI = PI_F;
    const static Ty ONE = 1.0f;
    const static Ty TWO = 2.0f;

    static __device__ __forceinline__ void sincos(Ty x, Ty *sptr, Ty *cptr)
    {
        sincosf(x, sptr, cptr);
    }
};

template <>
class Float<double>
{
public:
    using Ty = double;

    const static Ty TAU = TAU;
    const static Ty PI = PI;
    const static Ty ONE = 1.0;
    const static Ty TWO = 2.0;

    static __device__ __forceinline__ void sincos(Ty x, Ty *sptr, Ty *cptr)
    {
        sincos(x, sptr, cptr);
    }
};

/// @brief For the given vector type, get the scalar type.
/// @tparam Vector The vector type.
template <typename Vector>
class ScalarOf;

template <>
class ScalarOf<double2>
{
public:
    using FloatOps = Float<double>;
    using Ty = double;
};

template <>
class ScalarOf<float2>
{
public:
    using FloatOps = Float<float>;
    using Ty = float;
};

template <typename Complex>
__device__ inline Complex complex_add(Complex a, Complex b)
{
    return {a.x + b.x, a.y + b.y};
}

template <typename Complex>
__device__ inline Complex complex_sub(Complex a, Complex b)
{
    return {a.x - b.x, a.y - b.y};
}

template <typename Complex>
__device__ inline Complex complex_mul(Complex a, Complex b)
{
    return {a.x * b.x - a.y * b.y, a.x * b.y + a.y * b.x};
}

template <typename Complex>
__device__ inline Complex complex_mul_real(Complex a, typename ScalarOf<Complex>::Ty b)
{
    return {a.x * b, a.y * b};
}
