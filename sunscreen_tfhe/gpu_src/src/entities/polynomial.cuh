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
};

template <typename T>
class Polynomial
{
public:
    static uint32_t size(const PolynomialDegree &size_info)
    {
        return size_info.degree * sizeof(T);
    }

    static constexpr uint32_t align()
    {
        return alignof(T);
    }

    template <typename U>
    void fft(Polynomial<U> *res, const PolynomialDegree &degree);

    template <typename U>
    void ifft(Polynomial<U> *res, const PolynomialDegree &degree);

    T *coeffs()
    {
        return data;
    }

    const T *coeffs() const
    {
        return data;
    }

private:
    T data[0];
};

template <>
template <>
void Polynomial<uint64_t>::fft<Complex<double>>(
    Polynomial<Complex<double>> *res,
    const PolynomialDegree &degree)
{
    ScratchAllocation<Polynomial<double>> temp = scratch_alloc<Polynomial<double>, PolynomialDegree>(degree);

    // Cast out u64 thing polynomial to double
    for (uint32_t i = threadIdx.x; i < degree.degree; i += blockDim.x)
    {
        temp->coeffs()[i] = (double)this->coeffs()[i];
    }

    __syncthreads();

    twisted_fft_noreorder(temp->coeffs(), res->coeffs(), degree.degree);
}

template <>
template <>
void Polynomial<Complex<double>>::ifft<uint64_t>(
    Polynomial<uint64_t> *__restrict__ res,
    const PolynomialDegree &degree)
{
    PolynomialDegree n_div_2 = PolynomialDegree{degree.degree / 2};

    ScratchAllocation<Polynomial<Complex<double>>> temp = scratch_alloc<Polynomial<Complex<double>>, PolynomialDegree>(n_div_2);

    for (uint32_t i = threadIdx.x; i < degree.degree; i += blockDim.x)
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
        res->coeffs()[i] = (uint64_t)reinterpret_cast<double*>(res->coeffs())[i];
    }
}