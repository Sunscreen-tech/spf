#pragma once
#include <cuda/std/complex>
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
    __device__ explicit constexpr inline GgswCiphertext(PunBuf data) : m_data(data) {}

    __device__ static inline u32 size(const GlevSizeInfo &size_info)
    {
        return GlevCiphertext::size(size_info) * (std::get<0>(size_info).size.val + 1);
    }

    __device__ inline GlevCiphertext rows(u32 i, const GlevSizeInfo &size_info)
    {
        return DstArray<GlevCiphertext>(m_data).nth(i, size_info);
    }

    __device__ inline const GlevCiphertext rows(u32 i, const GlevSizeInfo &size_info) const
    {
        return DstArray<GlevCiphertext>(m_data).nth(i, size_info);
    }

    __device__ inline void fft(GgswCiphertextFft res, const GlevSizeInfo &size_info) const;

    __device__ static constexpr inline GgswCiphertext from_ptr(cuda::std::complex<f64> *ptr)
    {
        return GgswCiphertext(PunBuf::from_ptr(ptr));
    }

    __device__ static constexpr inline const GgswCiphertext from_ptr(const cuda::std::complex<f64> *ptr)
    {
        return GgswCiphertext(PunBuf::from_ptr(ptr));
    }

private:
    PunBuf m_data;
};

class GgswCiphertextFft
{
public:
    GgswCiphertextFft() = delete;
    __device__ explicit constexpr inline GgswCiphertextFft(PunBuf data) : m_data(data) {}

    __device__ static inline u32 size(const GlevSizeInfo &size_info)
    {
        return GlevCiphertextFft::size(size_info) * (std::get<0>(size_info).size.val + 1);
    }

    __device__ inline GlevCiphertextFft rows(u32 i, const GlevSizeInfo &size_info)
    {
        return DstArray<GlevCiphertextFft>(m_data).nth(i, size_info);
    }

    __device__ inline const GlevCiphertextFft rows(u32 i, const GlevSizeInfo &size_info) const
    {
        return DstArray<GlevCiphertextFft>(m_data).nth(i, size_info);
    }

    template <typename U>
    __device__ inline GgswCiphertext ifft(const GlevSizeInfo &size_info) const;

    __device__ static constexpr inline GgswCiphertextFft from_ptr(cuda::std::complex<f64> *ptr)
    {
        return GgswCiphertextFft(PunBuf::from_ptr(ptr));
    }

    __device__ static constexpr inline const GgswCiphertextFft from_ptr(const cuda::std::complex<f64> *ptr)
    {
        return GgswCiphertextFft(PunBuf::from_ptr(ptr));
    }

private:
    PunBuf m_data;
};

__device__ inline void GgswCiphertext::fft(GgswCiphertextFft res, const GlevSizeInfo &size_info) const {
    // Do the rows with the S_i*m term...
    for (u32 i = 0; i < std::get<0>(size_info).size.val; i++) {
        auto c_row = this->rows(i, size_info);
        auto fft_row = res.rows(i, size_info);

        c_row.fft(fft_row, size_info);
    }

    // ...and then the row with only the message
    auto c_row = this->rows(std::get<0>(size_info).size.val, size_info);
    auto fft_row = res.rows(std::get<0>(size_info).size.val, size_info);

    c_row.fft(fft_row, size_info);
}