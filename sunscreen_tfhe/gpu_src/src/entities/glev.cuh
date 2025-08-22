#pragma once
#include <cuda/std/complex>
#include <cstdint>
#include <tuple>

#include "dst_array.cuh"
#include "glwe.cuh"
#include "../params.cuh"
#include "../math/primitives.cuh"

class GlevCiphertextFft;

using GlevSizeInfo = std::tuple<GlweDef, RadixDecomposition>;

class GlevCiphertext
{
public:
    GlevCiphertext() = delete;
    __device__ explicit constexpr inline GlevCiphertext(cuda::std::complex<f64>* data): m_data(PunBuf(data)) {}
    __device__ explicit constexpr inline GlevCiphertext(PunBuf data): m_data(data) {}

    __device__ static inline u32 size(const GlevSizeInfo &size_info)
    {
        return GlweCiphertext::size(std::get<0>(size_info)) * std::get<1>(size_info).count.val;
    }

    __device__ constexpr inline GlweCiphertext decomps(u32 i, const GlevSizeInfo &size_info)
    {
        return DstArray<GlweCiphertext>(m_data).nth(i, std::get<0>(size_info));
    }

    __device__ constexpr inline const GlweCiphertext decomps(u32 i, const GlevSizeInfo &size_info) const
    {
        return DstArray<GlweCiphertext>(m_data).nth(i, std::get<0>(size_info));
    }

    __device__ inline void fft(GlevCiphertextFft out, const GlevSizeInfo &size_info) const;

    __device__ static constexpr inline GlevCiphertext from_ptr(cuda::std::complex<f64> *ptr) {
        return GlevCiphertext(PunBuf::from_ptr(ptr));
    }

    __device__ static constexpr inline const GlevCiphertext from_ptr(const cuda::std::complex<f64> *ptr) {
        return GlevCiphertext(PunBuf::from_ptr(ptr));
    }
private:
    PunBuf m_data;
};

class GlevCiphertextFft
{
public:
    GlevCiphertextFft() = delete;
    __device__ explicit constexpr inline GlevCiphertextFft(cuda::std::complex<f64>* data): m_data(PunBuf(data)) {}
    __device__ explicit constexpr inline GlevCiphertextFft(PunBuf data): m_data(data) {}

    __device__ static inline u32 size(const GlevSizeInfo &size_info)
    {
        return GlweCiphertextFft::size(std::get<0>(size_info)) * std::get<1>(size_info).count.val;
    }

    __device__ constexpr inline GlweCiphertextFft decomps(u32 i, const GlevSizeInfo &size_info)
    {
        return DstArray<GlweCiphertextFft>(m_data).nth(i, std::get<0>(size_info));
    }

    __device__ constexpr inline const GlweCiphertextFft decomps(u32 i, const GlevSizeInfo &size_info) const
    {
        return DstArray<GlweCiphertextFft>(m_data).nth(i, std::get<0>(size_info));
    }

    __device__ inline void ifft(GlevCiphertext out, const GlevSizeInfo &size_info) const {
        for (u32 i = 0; i < std::get<1>(size_info).count.val; i++)
        {
            auto d_fft_i = this->decomps(i, size_info);
            auto d_i = out.decomps(i, size_info);

            d_fft_i.ifft(d_i, std::get<0>(size_info));
        }
    }

    __device__ static constexpr inline GlevCiphertextFft from_ptr(cuda::std::complex<f64> *ptr) {
        return GlevCiphertextFft(PunBuf::from_ptr(ptr));
    }

    __device__ static constexpr inline const GlevCiphertextFft from_ptr(const cuda::std::complex<f64> *ptr) {
        return GlevCiphertextFft(PunBuf::from_ptr(ptr));
    }

private:
    PunBuf m_data;
};

__device__ inline void GlevCiphertext::fft(GlevCiphertextFft out, const GlevSizeInfo &size_info) const {
    for (u32 i = 0; i < std::get<1>(size_info).count.val; i++)
    {
        auto d_i = this->decomps(i, size_info);
        auto d_fft_i = out.decomps(i, size_info);

        d_i.fft(d_fft_i, std::get<0>(size_info));
    }
}