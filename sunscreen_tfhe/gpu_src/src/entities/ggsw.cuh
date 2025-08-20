#pragma once

#include <cstdint>
#include <tuple>

#include "punbuf.cuh"
#include "glev.cuh"
#include "../math/primitives.cuh"

class GgswCiphertextFft;

class GgswCiphertext
{
public:
    GgswCiphertext() = delete;
    __device__ explicit constexpr inline GgswCiphertext(std::complex<f64>* data): m_data(PunBuf(data)) {}
    __device__ explicit constexpr inline GgswCiphertext(PunBuf data): m_data(data) {}

    __device__ static inline uint32_t size(const GlevSizeInfo &size_info) {
        return GlevCiphertext::size(size_info) * (std::get<0>(size_info).size.val + 1);
    }

    __device__ inline GlevCiphertext rows(uint32_t i, const GlevSizeInfo &size_info) {
        return DstArray<GlevCiphertext>(m_data).nth(i, size_info);
    }

    __device__ inline const GlevCiphertext rows(uint32_t i, const GlevSizeInfo &size_info) const {
        return DstArray<GlevCiphertext>(m_data).nth(i, size_info);
    }

    __device__ inline GgswCiphertextFft fft(const GlevSizeInfo &size_info) const;
private:
    PunBuf m_data;
};

class GgswCiphertextFft {
public:
    GgswCiphertextFft() = delete;
    __device__ explicit constexpr inline GgswCiphertextFft(std::complex<f64>* data): m_data(PunBuf(data)) {}
    __device__ explicit constexpr inline GgswCiphertextFft(PunBuf data): m_data(data) {}

    __device__ static inline uint32_t size(const GlevSizeInfo &size_info) {
        return GlevCiphertextFft::size(size_info) * (std::get<0>(size_info).size.val + 1);
    }

    __device__ inline GlevCiphertextFft rows(uint32_t i, const GlevSizeInfo &size_info) {
        return DstArray<GlevCiphertextFft>(m_data).nth(i, size_info);
    }

    __device__ inline const GlevCiphertextFft rows(uint32_t i, const GlevSizeInfo &size_info) const {
        return DstArray<GlevCiphertextFft>(m_data).nth(i, size_info);
    }

    template <typename U>
    __device__ inline GgswCiphertext ifft(const GlevSizeInfo &size_info) const;
private:
    PunBuf m_data;
};
