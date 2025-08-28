#pragma once
#include <cuda/std/complex>
#include <tuple>

#include "dst_array.cuh"
#include "punbuf.cuh"
#include "ggsw.cuh"

class BootstrapKeyFft;

using BootstrapKeySizeInfo = std::tuple<LweDef, GlweDef, RadixDecomposition>;

class BootstrapKey
{
public:
    using BufTy = PunBuf;

    BootstrapKey() = delete;
    __device__ explicit constexpr inline BootstrapKey(BufTy data) : m_data(data) {}

    __device__ static inline u32 size(const BootstrapKeySizeInfo &size_info)
    {
        return std::get<0>(size_info).size.val * GgswCiphertext::size(std::tuple(std::get<1>(size_info), std::get<2>(size_info)));
    }

    /// @brief  Gets the i'th GGSW encrypted bit of the LWE secret key
    /// @param i
    /// @param size_info
    /// @return
    __device__ constexpr inline GgswCiphertext s(u32 i, const BootstrapKeySizeInfo &size_info)
    {
        return DstArray<GgswCiphertext>(m_data).nth(i, std::tuple(std::get<1>(size_info), std::get<2>(size_info)));
    }

    /// @brief  Gets the i'th GGSW encrypted bit of the LWE secret key
    /// @param i
    /// @param size_info
    /// @return
    __device__ constexpr inline const GgswCiphertext s(u32 i, const BootstrapKeySizeInfo &size_info) const
    {
        return DstArray<GgswCiphertext>(m_data).nth(i, std::tuple(std::get<1>(size_info), std::get<2>(size_info)));
    }

    __device__ static constexpr inline BootstrapKey from_ptr(cuda::std::complex<f64> *ptr)
    {
        return BootstrapKey(BufTy::from_ptr(ptr));
    }

    __device__ static constexpr inline const BootstrapKey from_ptr(const cuda::std::complex<f64> *ptr)
    {
        return BootstrapKey(BufTy::from_ptr(ptr));
    }

    __device__ inline void fft(BootstrapKeyFft out, const BootstrapKeySizeInfo &size_info) const;

private:
    BufTy m_data;
};

class BootstrapKeyFft
{
public:
    using BufTy = PunBuf;

    BootstrapKeyFft() = delete;
    __device__ explicit constexpr inline BootstrapKeyFft(BufTy data) : m_data(data) {}

    __device__ static inline u32 size(const BootstrapKeySizeInfo &size_info)
    {
        return std::get<0>(size_info).size.val * GgswCiphertextFft::size(std::tuple(std::get<1>(size_info), std::get<2>(size_info)));
    }

    /// @brief  Gets the i'th GGSW encrypted bit of the LWE secret key
    /// @param i
    /// @param size_info
    /// @return
    __device__ inline GgswCiphertextFft s(u32 i, const BootstrapKeySizeInfo &size_info)
    {
        return DstArray<GgswCiphertextFft>(m_data).nth(i, std::tuple(std::get<1>(size_info), std::get<2>(size_info)));
    }

    /// @brief  Gets the i'th GGSW encrypted bit of the LWE secret key
    /// @param i
    /// @param size_info
    /// @return
    __device__ inline const GgswCiphertextFft s(u32 i, const BootstrapKeySizeInfo &size_info) const
    {
        return DstArray<GgswCiphertextFft>(m_data).nth(i, std::tuple(std::get<1>(size_info), std::get<2>(size_info)));
    }

    __device__ static constexpr inline BootstrapKeyFft from_ptr(cuda::std::complex<f64> *ptr)
    {
        return BootstrapKeyFft(BufTy::from_ptr(ptr));
    }

    __device__ static constexpr inline const BootstrapKeyFft from_ptr(const cuda::std::complex<f64> *ptr)
    {
        return BootstrapKeyFft(BufTy::from_ptr(ptr));
    }

private:
    BufTy m_data;
};

__device__ inline void BootstrapKey::fft(BootstrapKeyFft out, const BootstrapKeySizeInfo &size_info) const {
    for (u32 i = 0; i < std::get<0>(size_info).size.val; i++) {
        auto s_i = this->s(i, size_info);
        auto s_i_fft = out.s(i, size_info);

        s_i.fft(s_i_fft, std::tuple(std::get<1>(size_info), std::get<2>(size_info)));
    }
}