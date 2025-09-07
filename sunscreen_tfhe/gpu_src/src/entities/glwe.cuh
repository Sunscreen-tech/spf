#pragma once

#include <cuda/std/complex>

#include "dst_array.cuh"
#include "polynomial.cuh"
#include "scratch.cuh"
#include "../math/math.cuh"
#include "../params.cuh"

class GlweCiphertextFft;

class GlweCiphertext
{
public:
    using BufTy = PunBuf;

    GlweCiphertext() = delete;
    __device__ explicit constexpr inline GlweCiphertext(BufTy data): m_data(data) { }

    __device__ static constexpr inline u32 size(const GlweDef &params)
    {
        return Polynomial::size(params.polynomial_degree()) * (params.size.val + 1);
    }

    __device__ constexpr inline Polynomial a_b(u32 i, const GlweDef &glwe)
    {
        return DstArray<Polynomial>(m_data).nth(i, glwe.polynomial_degree());
    }

    __device__ constexpr inline const Polynomial a_b(u32 i, const GlweDef &glwe) const
    {
        return DstArray<Polynomial>(m_data).nth(i, glwe.polynomial_degree());
    }

    __device__ inline void fft(GlweCiphertextFft out, const GlweDef &params, PerBlockStackAllocator &scratch) const;
    __device__ inline GlweCiphertextFft fft_inplace(const GlweDef &params) &&;

    __device__ static constexpr inline GlweCiphertext from_ptr(cuda::std::complex<double> *ptr) {
        return GlweCiphertext(BufTy::from_ptr(ptr));
    }

    __device__ static constexpr inline const GlweCiphertext from_ptr(const cuda::std::complex<double> *ptr) {
        return GlweCiphertext(BufTy::from_ptr(ptr));
    }

    __device__ inline void clone_into(GlweCiphertext other, const GlweDef &params) const
    {
        for (u32 i = 0; i < params.size.val; i++)
        {
            auto this_a_i = this->a_b(i, params);
            auto other_a_i = other.a_b(i, params);

            this_a_i.clone_into(other_a_i, params.polynomial_degree());
        }

        auto this_b = this->a_b(params.size.val, params);
        auto other_b = other.a_b(params.size.val, params);

        this_b.clone_into(other_b, params.polynomial_degree());
    }

    __device__ inline void clear(const GlweDef &params) {
        for (u32 i = 0; i <= params.size.val; i++) {
            auto a_i = this->a_b(i, params);

            a_i.clear(params.polynomial_degree());
        }
    }
private:
    BufTy m_data;
};

class GlweCiphertextFft
{
public:
    using BufTy = PunBuf;

    GlweCiphertextFft() = delete;
    __device__ explicit constexpr inline GlweCiphertextFft(BufTy data): m_data(data) { }

    __device__ static constexpr inline u32 size(const GlweDef &params)
    {
        return PolynomialFft::size(params.polynomial_degree()) * (params.size.val + 1);
    }

    __device__ constexpr inline PolynomialFft a_b(u32 i, const GlweDef &glwe)
    {
        return DstArray<PolynomialFft>(m_data).nth(i, glwe.polynomial_degree());
    }

    __device__ constexpr inline const PolynomialFft a_b(u32 i, const GlweDef &glwe) const
    {
        return DstArray<PolynomialFft>(m_data).nth(i, glwe.polynomial_degree());
    }

    __device__ inline void ifft(GlweCiphertext out, const GlweDef &params, PerBlockStackAllocator &scratch) const {
        // k `a` values and 1 `b` value.
        for (u32 i = 0; i <= params.size.val; i++)
        {
            auto a_fft_i = this->a_b(i, params);
            auto a_i = out.a_b(i, params);

            a_fft_i.ifft(a_i, params.polynomial_degree(), scratch);
        }
    }

    __device__ inline GlweCiphertext ifft_inplace(const GlweDef &params) && {
        for (u32 i = 0; i < params.size.val; i++)
        {
            auto a_fft_i = this->a_b(i, params);

            std::move(a_fft_i).ifft_inplace(params.polynomial_degree());
        }

        auto b_fft = this->a_b(params.size.val, params);

        std::move(b_fft).ifft_inplace(params.polynomial_degree());

        return GlweCiphertext(m_data);
    }

    __device__ static constexpr inline GlweCiphertextFft from_ptr(cuda::std::complex<f64> *ptr) {
        return GlweCiphertextFft(BufTy::from_ptr(ptr));
    }

    __device__ static constexpr inline const GlweCiphertextFft from_ptr(const cuda::std::complex<f64> *ptr) {
        return GlweCiphertextFft(BufTy::from_ptr(ptr));
    }

    __device__ constexpr inline cuda::std::complex<f64> *get_ptr() {
        return m_data.as_complex();
    }

    __device__ inline void clone_into(GlweCiphertextFft out, const GlweDef &params) const {
        for (u32 i = 0; i <= params.size.val; i++)
        {
            auto a_fft_i = this->a_b(i, params);
            auto a_i = out.a_b(i, params);

            a_fft_i.clone_into(a_i, params.polynomial_degree());
        }
    }

    __device__ inline void clear(const GlweDef &params) {
        for (u32 i = 0; i <= params.size.val; i++) {
            auto a_fft_i = this->a_b(i, params);

            a_fft_i.clear(params.polynomial_degree());
        }
    }

    __device__ inline void dbg(const GlweDef &params) {
        for (u32 i = 0; i <= params.size.val; i++) {
            this->a_b(i, params).dbg(params.polynomial_degree());
        }
    }
private:
    BufTy m_data;
};

__device__ inline void GlweCiphertext::fft(GlweCiphertextFft out, const GlweDef &params, PerBlockStackAllocator &scratch) const {
    // k + 1 polynomials in a GLWE ciphertext.
    for (u32 i = 0; i <= params.size.val; i++)
    {
        auto a_i = this->a_b(i, params);
        auto a_fft_i = out.a_b(i, params);

        a_i.fft(a_fft_i, params.polynomial_degree(), scratch);
    }
}


__device__ inline GlweCiphertextFft GlweCiphertext::fft_inplace(const GlweDef &params) && {
    // k + 1 polynomials in a GLWE ciphertext.
    for (u32 i = 0; i <= params.size.val; i++)
    {
        auto a_i = this->a_b(i, params);

        std::move(a_i).fft_inplace(params.polynomial_degree());
    }

    return GlweCiphertextFft(m_data);
}