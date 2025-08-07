#pragma once

#include <cstdint>
#include <tuple>

#include "glev.cuh"

template <typename T>
class GgswCiphertextFft;

template <typename T>
class GgswCiphertext
{
public:
    GgswCiphertext() = delete;

    __device__ static inline uint32_t size(const GlevSizeInfo &size_info) {
        return GlevCiphertext<T>::size(size_info) * (std::get<0>(size_info).size.val + 1)
    }

    __device__ static constexpr inline size_t align() {
        return alignof(T);
    }

    __device__ inline GlevCiphertext<T>* rows(uint32_t i, const GlevSizeInfo &size_info) {
        auto as_array = reinterpret_cast<DstArray<GlevCiphertext<T>> *>(this)
        return as_array->nth(i, size_info);
    }

    __device__ inline const GlevCiphertext<T>* rows(uint32_t i, const GlevSizeInfo &size_info) const {
        auto as_array = reinterpret_cast<const DstArray<GlevCiphertext<T>> *>(this);
        return as_array->nth(i, size_info);
    }

    template <typename U>
    __device__ inline GlevCiphertextFft<U> *fft(const GlevSizeInfo &size_info) const;
private:
    uint8_t data[0];
};

template <typename T>
class GgswCiphertextFft {
public:
    GgswCiphertextFft() = delete;

    __device__ static inline uint32_t size(const GlevSizeInfo &size_info) {
        return GlevCiphertextFft<T>::size(size_info) * (std::get<0>(size_info).size.val + 1);
    }

    __device__ static constexpr inline size_t align() {
        return alignof(T);
    }

    __device__ inline GlevCiphertextFft<T>* rows(uint32_t i, const GlevSizeInfo &size_info) {
        auto as_array = reinterpret_cast<DstArray<GlevCiphertextFft<T>> *>(this)
        return as_array->nth(i, size_info);
    }

    __device__ inline const GlevCiphertextFft<T>* rows(uint32_t i, const GlevSizeInfo &size_info) const {
        auto as_array = reinterpret_cast<const DstArray<GlevCiphertextFft<T>> *>(this);
        return as_array->nth(i, size_info);
    }

    template <typename U>
    __device__ inline GgswCiphertext<U> *ifft(const GlevSizeInfo &size_info) const;
private:
    uint8_t data[0];
};
