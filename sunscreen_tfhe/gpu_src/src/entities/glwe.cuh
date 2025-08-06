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

    __device__ inline uint32_t size(const GlweDef &params)
    {
        return Polynomial<T>::size(params.polynomial_degree()) * (params.size + 1);
    }

    __device__ constexpr inline size_t align()
    {
        return alignof(T);
    }

    __device__ inline Polynomial<T> *a_b(uint32_t i, const GlweDef &glwe)
    {
        auto as_array = reinterpret_cast<DstArray<Polynomial<T>> *>(this, glwe.polynomial_degree());
        return as_array->nth(i);
    }

    __device__ inline const Polynomial<T> *a_b(uint32_t i, const GlweDef &glwe) const
    {
        auto as_array = reinterpret_cast<const DstArray<Polynomial<T>> *>(this, glwe.polynomial_degree());
        return as_array->nth(i);
    }

private:
    uint8_t data[0];
};
