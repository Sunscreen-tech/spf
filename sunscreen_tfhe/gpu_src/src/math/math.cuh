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

    // TODO: This is buggy
    static __device__ inline void sincos(Ty x, Ty *sptr, Ty *cptr)
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

    // TODO: This is buggy
    static __device__ inline void sincos(Ty x, Ty *sptr, Ty *cptr)
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

// template <typename Complex>
// __device__ inline Complex complex_add(Complex a, Complex b)
// {
//     return {a.x + b.x, a.y + b.y};
// }

// template <typename Complex>
// __device__ inline Complex complex_sub(Complex a, Complex b)
// {
//     return {a.x - b.x, a.y - b.y};
// }

template <typename Complex>
__device__ inline Complex complex_mul(Complex a, Complex b)
{
    return {a.x * b.x - a.y * b.y, a.x * b.y + a.y * b.x};
}

// template <typename Complex>
// __device__ inline Complex complex_mul_real(Complex a, typename ScalarOf<Complex>::Ty b)
// {
//     return {a.x * b, a.y * b};
// }

template <typename S>
class Complex
{
public:
    
};

template <>
class Complex<double>
{
public:
    using T = double;
    using VecT = double2;

    /// @brief Constructs an in-initialized Complex value.
    __device__ Complex() {}
    __device__ Complex(VecT inner) : val(inner) {}

    __device__ inline Complex<T> operator+(const Complex<T> &rhs) const
    {
        return Complex({this->val.x + rhs.val.x, this->val.y + rhs.val.y});
    }

    __device__ inline Complex<T> operator-(const Complex<T> &rhs) const
    {
        return Complex({this->val.x - rhs.val.x, this->val.y - rhs.val.y});
    }

    __device__ inline Complex<T> operator*(const Complex<T> &rhs) const
    {
        return Complex({this->val.x * rhs.val.x - this->val.y * rhs.val.y,
                        this->val.x * rhs.val.y + this->val.y * rhs.val.x});
    }

    __device__ inline Complex<T> operator*(const T &rhs) const
    {
        return Complex({this->val.x * rhs,
                        this->val.y * rhs});
    }

    __device__ inline T& re() {
        return this->val.x;
    }

    __device__ inline T& im() {
        return this->val.y;
    }

    __device__ inline const T& re() const {
        return this->val.x;
    }

    __device__ inline const T& im() const {
        return this->val.y;
    }

    __device__ inline VecT& inner() {
        return this->val;
    }

private:
    VecT val;
};

template <>
class Complex<float>
{
public:
    using T = float;
    using VecT = float2;

    /// @brief Constructs an in-initialized Complex value.
    __device__ Complex() {}
    __device__ Complex(VecT inner) : val(inner) {}

    __device__ inline Complex<T> operator+(const Complex<T> &rhs) const
    {
        return Complex({this->val.x + rhs.val.x, this->val.y + rhs.val.y});
    }

    __device__ inline Complex<T> operator-(const Complex<T> &rhs) const
    {
        return Complex({this->val.x - rhs.val.x, this->val.y - rhs.val.y});
    }

    __device__ inline Complex<T> operator*(const Complex<T> &rhs) const
    {
        return Complex({this->val.x * rhs.val.x - this->val.y * rhs.val.y,
                        this->val.x * rhs.val.y + this->val.y * rhs.val.x});
    }

    __device__ inline Complex<T> operator*(const T &rhs) const
    {
        return Complex({this->val.x * rhs,
                        this->val.y * rhs});
    }


    __device__ inline T& re() {
        return this->val.x;
    }

    __device__ inline T& im() {
        return this->val.y;
    }

    __device__ inline const T& re() const {
        return this->val.x;
    }

    __device__ inline const T& im() const {
        return this->val.y;
    }
private:
    VecT val;
};