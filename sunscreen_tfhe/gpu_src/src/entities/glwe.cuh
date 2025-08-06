#pragma once

#include <cstdint>

#include "dst_array.cuh"
#include "polynomial.cuh"
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

private:
    uint8_t data[0];
};
