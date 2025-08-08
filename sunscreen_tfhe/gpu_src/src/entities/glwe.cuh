#pragma once

#include <cstdint>

#include "dst_array.cuh"
#include "polynomial.cuh"
#include "../math/math.cuh"
#include "../params.cuh"

template <typename T>
class GlweCiphertextFft;

template <typename T>
class GlweCiphertext
{
public:
    GlweCiphertext() = delete;

    __device__ static inline uint32_t size(const GlweDef &params)
    {
        return Polynomial<T>::size(params.polynomial_degree()) * (params.size.val + 1);
    }

    __device__ static constexpr inline size_t align()
    {
        return alignof(T);
    }

    __device__ inline Polynomial<T> *a_b(uint32_t i, const GlweDef &glwe)
    {
        auto as_array = reinterpret_cast<DstArray<Polynomial<T>> *>(this);
        return as_array->nth(i, glwe.polynomial_degree().val);
    }

    __device__ inline const Polynomial<T> *a_b(uint32_t i, const GlweDef &glwe) const
    {
        auto as_array = reinterpret_cast<const DstArray<Polynomial<T>> *>(this);
        return as_array->nth(i, glwe.polynomial_degree().val);
    }

    template <typename U>
    __device__ inline void fft(GlweCiphertextFft<U> *out, const GlweDef &params) const;

private:
    uint8_t data[0];
};

template <typename T>
class GlweCiphertextFft
{
public:
    GlweCiphertextFft() = delete;

    __device__ static inline uint32_t size(const GlweDef &params)
    {
        return PolynomialFft<T>::size(params.polynomial_degree()) * (params.size.val + 1);
    }

    __device__ static constexpr inline size_t align()
    {
        return alignof(T);
    }

    __device__ inline PolynomialFft<T> *a_b(uint32_t i, const GlweDef &glwe)
    {
        auto as_array = reinterpret_cast<DstArray<PolynomialFft<T>> *>(this);
        return as_array->nth(i, glwe.polynomial_degree().val);
    }

    __device__ inline const PolynomialFft<T> *a_b(uint32_t i, const GlweDef &glwe) const
    {
        auto as_array = reinterpret_cast<const DstArray<PolynomialFft<T>> *>(this);
        return as_array->nth(i, glwe.polynomial_degree().val);
    }

    template <typename U>
    __device__ inline void ifft(GlweCiphertext<U> *out, const GlweDef &params) const;
private:
    uint8_t data[0];
};

template <>
template <>
__device__ inline void GlweCiphertext<uint64_t>::fft<Complex<double>>(
    GlweCiphertextFft<Complex<double>> *out,
    const GlweDef &params) const
{
    for (uint32_t i = 0; i < params.size.val; i++)
    {
        auto a_i = this->a_b(i, params);
        auto a_fft_i = out->a_b(i, params);

        a_i->fft(a_fft_i, params.polynomial_degree());
    }

    auto a_i = this->a_b(params.size.val, params);
    auto a_fft_i = out->a_b(params.size.val, params);

    a_i->fft(a_fft_i, params.polynomial_degree());
}

template <>
template <>
__device__ inline void GlweCiphertextFft<Complex<double>>::ifft<uint64_t>(
    GlweCiphertext<uint64_t> *out,
    const GlweDef &params) const
{
    for (uint32_t i = 0; i < params.size.val; i++)
    {
        auto a_fft_i = this->a_b(i, params);
        auto a_i = out->a_b(i, params);

        a_fft_i->ifft(a_i, params.polynomial_degree());
    }

    auto a_fft_i = this->a_b(params.size.val, params);
    auto a_i = out->a_b(params.size.val, params);

    a_fft_i->ifft(a_i, params.polynomial_degree());
}
