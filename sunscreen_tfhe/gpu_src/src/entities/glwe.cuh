#pragma once

#include <cuda/std/complex>
#include <cstdint>

#include "dst_array.cuh"
#include "polynomial.cuh"
#include "../math/math.cuh"
#include "../params.cuh"

class GlweCiphertextFft;

class GlweCiphertext
{
public:
    GlweCiphertext() = delete;
    __device__ explicit constexpr inline GlweCiphertext(PunBuf data): m_data(data) { }

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

    __device__ inline void fft(GlweCiphertextFft out, const GlweDef &params) const;

    __device__ static constexpr inline GlweCiphertext from_ptr(cuda::std::complex<double> *ptr) {
        return GlweCiphertext(PunBuf::from_ptr(ptr));
    }

    __device__ static constexpr inline const GlweCiphertext from_ptr(const cuda::std::complex<double> *ptr) {
        return GlweCiphertext(PunBuf::from_ptr(ptr));
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

private:
    PunBuf m_data;
};

class GlweCiphertextFft
{
public:
    GlweCiphertextFft() = delete;
    __device__ explicit constexpr inline GlweCiphertextFft(PunBuf data): m_data(data) { }

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

    __device__ inline void ifft(GlweCiphertext out, const GlweDef &params) const {
        for (u32 i = 0; i < params.size.val; i++)
        {
            auto a_fft_i = this->a_b(i, params);
            auto a_i = out.a_b(i, params);

            a_fft_i.ifft(a_i, params.polynomial_degree());
        }

        auto b_fft = this->a_b(params.size.val, params);
        auto b = out.a_b(params.size.val, params);

        b_fft.ifft(b, params.polynomial_degree());
    }

    __device__ static constexpr inline const GlweCiphertextFft from_ptr(cuda::std::complex<f64> *ptr) {
        return GlweCiphertextFft(PunBuf::from_ptr(ptr));
    }

    __device__ inline void clone_into(GlweCiphertextFft out, const GlweDef &params) const {
        for (u32 i = 0; i < params.size.val; i++)
        {
            auto a_fft_i = this->a_b(i, params);
            auto a_i = out.a_b(i, params);

            a_fft_i.clone_into(a_i, params.polynomial_degree());
        }

        auto b_fft = this->a_b(params.size.val, params);
        auto b = out.a_b(params.size.val, params);

        b_fft.clone_into(b, params.polynomial_degree());
    }
private:
    PunBuf m_data;
};

__device__ inline void GlweCiphertext::fft(GlweCiphertextFft out, const GlweDef &params) const {
    for (u32 i = 0; i < params.size.val; i++)
    {
        auto a_i = this->a_b(i, params);
        auto a_fft_i = out.a_b(i, params);

        a_i.fft(a_fft_i, params.polynomial_degree());
    }

    auto a_i = this->a_b(params.size.val, params);
    auto a_fft_i = out.a_b(params.size.val, params);

    a_i.fft(a_fft_i, params.polynomial_degree());
}