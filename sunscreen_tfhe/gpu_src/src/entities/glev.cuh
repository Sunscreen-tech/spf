#pragma once
#include <cuda/std/complex>
#include <cuda/std/tuple>

#include "dst_array.cuh"
#include "glwe.cuh"
#include "../params.cuh"
#include "../math/primitives.cuh"

class GlevCiphertextFft;

using GlevSizeInfo = cuda::std::tuple<GlweDef, RadixDecomposition>;

class GlevCiphertext
{
public:
    using BufTy = PunBuf;

    GlevCiphertext() = delete;
<<<<<<< HEAD
    __device__ explicit constexpr inline GlevCiphertext(cuda::std::complex<f64>* data): m_data(BufTy(data)) {}
    __device__ explicit constexpr inline GlevCiphertext(BufTy data): m_data(data) {}
=======
    __device__ explicit constexpr inline GlevCiphertext(cuda::std::complex<f64> *data) : m_data(BufTy(data)) {}
    __device__ explicit constexpr inline GlevCiphertext(BufTy data) : m_data(data) {}
>>>>>>> 12ba245 (tests pass)

    __device__ static inline u32 size(const GlevSizeInfo &size_info)
    {
        return GlweCiphertext::size(cuda::std::get<0>(size_info)) * cuda::std::get<1>(size_info).count.val;
    }

    __device__ constexpr inline GlweCiphertext decomps(u32 i, const GlevSizeInfo &size_info)
    {
        return DstArray<GlweCiphertext>(m_data).nth(i, cuda::std::get<0>(size_info));
    }

    __device__ constexpr inline const GlweCiphertext decomps(u32 i, const GlevSizeInfo &size_info) const
    {
        return DstArray<GlweCiphertext>(m_data).nth(i, cuda::std::get<0>(size_info));
    }

    __device__ inline void fft(GlevCiphertextFft out, const GlevSizeInfo &size_info, PerBlockStackAllocator &scratch) const;

<<<<<<< HEAD
    __device__ static constexpr inline GlevCiphertext from_ptr(cuda::std::complex<f64> *ptr) {
        return GlevCiphertext(BufTy::from_ptr(ptr));
    }

    __device__ static constexpr inline const GlevCiphertext from_ptr(const cuda::std::complex<f64> *ptr) {
=======
    __device__ static constexpr inline GlevCiphertext from_ptr(cuda::std::complex<f64> *ptr)
    {
        return GlevCiphertext(BufTy::from_ptr(ptr));
    }

    __device__ static constexpr inline const GlevCiphertext from_ptr(const cuda::std::complex<f64> *ptr)
    {
>>>>>>> 12ba245 (tests pass)
        return GlevCiphertext(BufTy::from_ptr(ptr));
    }

private:
    BufTy m_data;
};

class GlevCiphertextFft
{
public:
    using BufTy = PunBuf;

    GlevCiphertextFft() = delete;
<<<<<<< HEAD
    __device__ explicit constexpr inline GlevCiphertextFft(cuda::std::complex<f64>* data): m_data(BufTy(data)) {}
    __device__ explicit constexpr inline GlevCiphertextFft(BufTy data): m_data(data) {}
=======
    __device__ explicit constexpr inline GlevCiphertextFft(cuda::std::complex<f64> *data) : m_data(BufTy(data)) {}
    __device__ explicit constexpr inline GlevCiphertextFft(BufTy data) : m_data(data) {}
>>>>>>> 12ba245 (tests pass)

    __device__ static inline u32 size(const GlevSizeInfo &size_info)
    {
        return GlweCiphertextFft::size(cuda::std::get<0>(size_info)) * cuda::std::get<1>(size_info).count.val;
    }

    __device__ constexpr inline GlweCiphertextFft decomps(u32 i, const GlevSizeInfo &size_info)
    {
        return DstArray<GlweCiphertextFft>(m_data).nth(i, cuda::std::get<0>(size_info));
    }

    __device__ constexpr inline const GlweCiphertextFft decomps(u32 i, const GlevSizeInfo &size_info) const
    {
        return DstArray<GlweCiphertextFft>(m_data).nth(i, cuda::std::get<0>(size_info));
    }

    __device__ inline void ifft(GlevCiphertext out, const GlevSizeInfo &size_info, PerBlockStackAllocator &scratch) const
    {
        for (u32 i = 0; i < cuda::std::get<1>(size_info).count.val; i++)
        {
            auto d_fft_i = this->decomps(i, size_info);
            auto d_i = out.decomps(i, size_info);

            d_fft_i.ifft(d_i, cuda::std::get<0>(size_info), scratch);
        }
    }

    __device__ static constexpr inline GlevCiphertextFft from_ptr(cuda::std::complex<f64> *ptr)
    {
        return GlevCiphertextFft(BufTy::from_ptr(ptr));
    }

    __device__ static constexpr inline const GlevCiphertextFft from_ptr(const cuda::std::complex<f64> *ptr)
    {
        return GlevCiphertextFft(BufTy::from_ptr(ptr));
    }

private:
    BufTy m_data;
};

__device__ inline void GlevCiphertext::fft(GlevCiphertextFft out, const GlevSizeInfo &size_info, PerBlockStackAllocator &scratch) const
{
    for (u32 i = 0; i < cuda::std::get<1>(size_info).count.val; i++)
    {
        auto d_i = this->decomps(i, size_info);
        auto d_fft_i = out.decomps(i, size_info);

        d_i.fft(d_fft_i, cuda::std::get<0>(size_info), scratch);
    }
}