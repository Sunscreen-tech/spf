#pragma once

#include <cstdint>
#include <tuple>

#include "glwe.cuh"
#include "../params.cuh"

template <typename T>
class GlevCiphertext
{
public:
    GlevCiphertext() = delete;

    __device__ inline uint32_t size(const std::tuple<GlweDef, RadixDecomposition> &size_info)
    {
        return GlweCiphertext<T>::size(size_info.get<0>()) * size_info.get<1>().count;
    }

    __device__ constexpr inline size_t align()
    {
        return alignof(T);
    }

    __device__ GlweCiphertext<T> *decomps(uint32_t i, const std::tuple<GlweDef, RadixDecomposition> &size_info)
    {
        auto as_array = reinterpret_cast<DstArray<GlweCiphertext<T>> *>(this, size_info.get<0>());
        return as_array->nth(i)
    }

private:
    uint8_t data[0];
};
