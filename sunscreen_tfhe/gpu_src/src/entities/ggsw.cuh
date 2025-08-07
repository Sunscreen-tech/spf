#pragma once

#include <cstdint>
#include <tuple>

#include "glev.cuh"

template <typename T>
class GgswCiphertext
{
public:
    GgswCiphertext() = delete;

    __device__ inline uint32_t size(const GlevSizeInfo &size_info) {
        return GlevCiphertext<T>::size(size_info) * (size_info.get<0>().size + 1)
    }

    __device__ constexpr inline size_t align() {
        return alignof(T);
    }

    __device__ inline GlevCiphertext<T>* rows(uint32_t i, const GlevSizeInfo &size_info) {
        auto as_array = reinterpret_cast<DstArray<GlevCiphertext<T>> *>(this)
        return as_array->nth(i, size_info.get<0>());
    }

    __device__ inline const GlevCiphertext<T>* rows(uint32_t i, const GlevSizeInfo &size_info) const {
        auto as_array = reinterpret_cast<const DstArray<GlevCiphertext<T>> *>(this);
        return as_array->nth(i, size_info.get<0>());
    }
private:
    uint8_t data[0];
};