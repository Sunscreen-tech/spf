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
    using BufTy = PunBuf;

    GgswCiphertext() = delete;
    __device__ explicit constexpr inline GgswCiphertext(BufTy data) : m_data(data) {}

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
        return GgswCiphertext(BufTy::from_ptr(ptr));
    }

    __device__ static constexpr inline const GgswCiphertext from_ptr(const cuda::std::complex<f64> *ptr)
    {
        return GgswCiphertext(BufTy::from_ptr(ptr));
    }

private:
    BufTy m_data;
};

class GgswCiphertextFft
{
public:
    using BufTy = PunBuf;

    GgswCiphertextFft() = delete;
    __device__ explicit constexpr inline GgswCiphertextFft(BufTy data) : m_data(data) {}

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

    __device__ inline void ifft(GgswCiphertext res, const GlevSizeInfo &size_info) const;

    __device__ static constexpr inline GgswCiphertextFft from_ptr(cuda::std::complex<f64> *ptr)
    {
        return GgswCiphertextFft(BufTy::from_ptr(ptr));
    }

    __device__ static constexpr inline const GgswCiphertextFft from_ptr(const cuda::std::complex<f64> *ptr)
    {
        return GgswCiphertextFft(BufTy::from_ptr(ptr));
    }

private:
    BufTy m_data;
};

__device__ inline void GgswCiphertext::fft(GgswCiphertextFft res, const GlevSizeInfo &size_info) const {
    // FFT the k + 1 rows in the GGSW. Hence `<=`.
    for (u32 i = 0; i <= std::get<0>(size_info).size.val; i++) {
        auto c_row = this->rows(i, size_info);
        auto fft_row = res.rows(i, size_info);

        c_row.fft(fft_row, size_info);
    }
}

__device__ inline void GgswCiphertextFft::ifft(GgswCiphertext res, const GlevSizeInfo &size_info) const {
    // IFFT the k + 1 rows in the GGSW. Hence `<=`.
    for (u32 i = 0; i <= std::get<0>(size_info).size.val; i++) {
        auto c_row = this->rows(i, size_info);
        auto fft_row = res.rows(i, size_info);

        c_row.ifft(fft_row, size_info);
    }
}