#pragma once

#include <cstdint>
#include <tuple>

#include "glev.cuh"

template <typename T>
class GgswCiphertext
{
public:
    GgswCiphertext() = delete;

    __device__ inline uint32_t size(const std::tuple<GlweDef, RadixDecomposition> &size_info) {
        return GlevCiphertext<T>::size(size_info) * (size_info.get<0>().size + 1)
    }
private:
    uint8_t data[0];
};