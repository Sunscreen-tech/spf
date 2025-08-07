#pragma once

#include <cstdint>
#include <tuple>

#include "glwe.cuh"
#include "../params.cuh"

template <typename T>
class GlevCiphertextFft;

using GlevSizeInfo = std::tuple<GlweDef, RadixDecomposition>;

template <typename T>
class GlevCiphertext
{
public:
    GlevCiphertext() = delete;

    __device__ static inline uint32_t size(const GlevSizeInfo &size_info)
    {
        return GlweCiphertext<T>::size(std::get<0>(size_info)) * std::get<1>(size_info).count.val;
    }

    __device__ static constexpr inline size_t align()
    {
        return alignof(T);
    }

    __device__ GlweCiphertext<T> *decomps(uint32_t i, const GlevSizeInfo &size_info)
    {
        auto as_array = reinterpret_cast<DstArray<GlweCiphertext<T>> *>(this); 
        return as_array->nth(i, std::get<0>(size_info));
    }

    __device__ const GlweCiphertext<T> *decomps(uint32_t i, const GlevSizeInfo &size_info) const
    {
        auto as_array = reinterpret_cast<const DstArray<GlweCiphertext<T>> *>(this);
        return as_array->nth(i, std::get<0>(size_info));
    }

    template <typename U>
    __device__ inline void fft(GlevCiphertextFft<U> *out, const GlevSizeInfo &size_info) const;

private:
    uint8_t data[0];
};

template <typename T>
class GlevCiphertextFft
{
public:
    GlevCiphertextFft() = delete;

    __device__ static inline uint32_t size(const GlevSizeInfo &size_info)
    {
        return GlweCiphertextFft<T>::size(std::get<0>(size_info)) * std::get<1>(size_info).count.val;
    }

    __device__ static constexpr inline size_t align()
    {
        return alignof(T);
    }

    __device__ GlweCiphertextFft<T> *decomps(uint32_t i, const GlevSizeInfo &size_info)
    {
        auto as_array = reinterpret_cast<DstArray<GlweCiphertextFft<T>> *>(this);
        return as_array->nth(i, std::get<0>(size_info));
    }

    __device__ const GlweCiphertextFft<T> *decomps(uint32_t i, const GlevSizeInfo &size_info) const
    {
        auto as_array = reinterpret_cast<const DstArray<GlweCiphertextFft<T>> *>(this);
        return as_array->nth(i, std::get<0>(size_info));
    }

    template <typename U>
    __device__ inline void ifft(GlevCiphertext<U> *out, const GlevSizeInfo &size_info) const;

private:
    uint8_t data[0];
};

template <>
template <>
__device__ inline void GlevCiphertext<uint64_t>::fft(
    GlevCiphertextFft<Complex<double>> *out,
    const GlevSizeInfo &size_info) const
{
    for (uint32_t i = 0; i < std::get<1>(size_info).count.val; i++)
    {
        auto d_i = this->decomps(i, size_info);
        auto d_fft_i = out->decomps(i, size_info);

        d_i->fft(d_fft_i, std::get<0>(size_info));
    }
}

template <>
template <>
__device__ inline void GlevCiphertextFft<Complex<double>>::ifft(
    GlevCiphertext<uint64_t> *out,
    const GlevSizeInfo &size_info) const
{
    for (uint32_t i = 0; i < std::get<1>(size_info).count.val; i++)
    {
        auto d_fft_i = this->decomps(i, size_info);
        auto d_i = out->decomps(i, size_info);

        d_fft_i->ifft(d_i, std::get<0>(size_info));
    }
}