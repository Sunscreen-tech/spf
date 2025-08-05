#pragma once
#include <cstdint>

#include "../math/math.cuh"
#include "dst.cuh"
#include "../params.h"
#include "../math/simd.cuh"
#include "../math/fft/negacyclic.cuh"
#include "../iter_tools.cuh"

struct PolynomialDegree
{
    uint32_t degree;

    __device__ inline PolynomialDegree(uint32_t degree): degree(degree) {}
};

template <typename T>
class PolynomialFft;

template <typename T>
class Polynomial
{
public:
    __device__ static inline uint32_t size(const PolynomialDegree &size_info)
    {
        return size_info.degree * sizeof(T);
    }

    __device__ static inline constexpr uint32_t align()
    {
        return alignof(T);
    }

    template <typename U>
    __device__ inline void fft(PolynomialFft<U> *res, const PolynomialDegree &degree) const;

    __device__ inline T *coeffs()
    {
        return data;
    }

    __device__ inline const T *coeffs() const
    {
        return data;
    }

private:
    T data[0];
};

template <typename T>
class PolynomialFft
{
public:
    __device__ static inline uint32_t size(const PolynomialDegree &size_info)
    {
        // Add 64 elements to support FFTs up to 4096.
        return (size_info.degree / 2) * sizeof(T);
    }
    
    __device__ static inline constexpr uint32_t align()
    {
        return alignof(T);
    }

    template <typename U>
    __device__ inline void ifft(Polynomial<U> *res, const PolynomialDegree &degree) const;

    __device__ inline T *coeffs()
    {
        return data;
    }

    __device__ inline const T *coeffs() const
    {
        return data;
    }
private:
    T data[0];
};

template <>
template <>
__device__ inline void Polynomial<uint64_t>::fft<Complex<double>>(
    PolynomialFft<Complex<double>> *res,
    const PolynomialDegree &degree) const
{
    ScratchAllocation<Polynomial<double>> temp = scratch_alloc<Polynomial<double>, PolynomialDegree>(degree);

    // Cast our u64 polynomial to double
    BLOCK_FOR_EACH(i, degree.degree)
    {
        temp->coeffs()[i] = (double)this->coeffs()[i];
    }

    __syncthreads();

    twisted_fft_noreorder(temp->coeffs(), res->coeffs(), degree.degree);
}

template <>
template <>
__device__ inline void PolynomialFft<Complex<double>>::ifft<uint64_t>(
    Polynomial<uint64_t> *__restrict__ res,
    const PolynomialDegree &degree) const
{
    PolynomialDegree n_div_2 = PolynomialDegree{degree.degree / 2};

    ScratchAllocation<Polynomial<Complex<double>>> temp = scratch_alloc<Polynomial<Complex<double>>, PolynomialDegree>(n_div_2);

    BLOCK_FOR_EACH(i, degree.degree)
    {
        temp->coeffs()[i] = this->coeffs()[i];
    }

    __syncthreads();

    // We abuse the output buffer by treating it as memory pointing to  double* values.
    // This is okay because sizeof(uint64_t) == sizeof(double).
    twisted_ifft_noreorder(temp->coeffs(), reinterpret_cast<Polynomial<double> *>(res)->coeffs(), degree.degree);

    // We again abuse the output buffer by treating it as a double*.
    inplace_reduce_mod_q_pow_2<double, 64>(
        reinterpret_cast<double*>(res->coeffs()),
        degree.degree);

    // Finally, we cast each value from double to uint64_t
    BLOCK_FOR_EACH(i, degree.degree)
    {
        // The result is on the signed torus [-q/2, q/2). Cast to a signed integer
        // then bitcast back to unsigned to get back to [0, q).
        res->coeffs()[i] = normalize_q_div_2_torus<double, uint64_t>(reinterpret_cast<double*>(res->coeffs())[i]);
    }
}
