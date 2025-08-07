#pragma once
#include <cstdint>

#include "../math/math.cuh"
#include "../params.cuh"
#include "../math/simd.cuh"
#include "../math/fft/negacyclic.cuh"
#include "../iter_tools.cuh"

template <typename T>
class PolynomialFft;

template <typename T>
class Polynomial
{
public:
    __device__ static inline uint32_t size(const PolynomialDegree &size_info)
    {
        return size_info.val * sizeof(T);
    }

    __device__ static inline constexpr uint32_t align()
    {
        return alignof(T);
    }

    __device__ inline T *coeffs()
    {
        return reinterpret_cast<T *>(data);
    }

    __device__ inline const T *coeffs() const
    {
        return reinterpret_cast<const T *>(data);
    }

    template <typename U>
    __device__ inline void fft(PolynomialFft<U> *res, const PolynomialDegree &degree) const;

    template <typename U>
    __device__ inline PolynomialFft<U> *fft_inplace(const PolynomialDegree &degree);

private:
    uint8_t data[0];
};

template <typename T>
class PolynomialFft
{
public:
    __device__ static inline uint32_t size(const PolynomialDegree &size_info)
    {
        // Add 64 elements to support FFTs up to 4096.
        return (size_info.val / 2) * sizeof(T);
    }

    __device__ static inline constexpr uint32_t align()
    {
        return alignof(T);
    }

    __device__ inline T *coeffs()
    {
        return reinterpret_cast<T *>(data);
    }

    __device__ inline const T *coeffs() const
    {
        return reinterpret_cast<const T *>(data);
    }

    template <typename U>
    __device__ inline void ifft(Polynomial<U> *res, const PolynomialDegree &degree) const;

    template <typename U>
    __device__ inline Polynomial<U> *ifft_inplace(const PolynomialDegree &degree);

private:
    uint8_t data[0];
};

template <>
template <>
__device__ inline void Polynomial<uint64_t>::fft<Complex<double>>(
    PolynomialFft<Complex<double>> *res,
    const PolynomialDegree &degree) const
{
    auto s_in = get_fft_scratch<double>();

    // Cast our u64 polynomial to double
    BLOCK_FOR_EACH(i, degree.val)
    {
        s_in[i] = (double)this->coeffs()[i];
    }

    __syncthreads();

    // twisted_fft operated in-place and returns s_in reinterpreted
    // as Complex<double>*
#ifdef FFT_NO_REORDER
    auto s_out = twisted_fft_noreorder(s_in, degree.degree);
#else
    auto s_out = twisted_fft(s_in, degree.val);
#endif

    BLOCK_COPY(res->coeffs(), s_out, degree.val / 2);
}

template <>
template <>
__device__ inline PolynomialFft<Complex<double>> *Polynomial<uint64_t>::fft_inplace(const PolynomialDegree &degree)
{
    auto s_cast = reinterpret_cast<double *>(this);

    BLOCK_FOR_EACH(i, degree.val)
    {
        s_cast[i] = (double)this->coeffs()[i];
    }

    auto s_out = twisted_fft(s_cast, degree.val);

    return reinterpret_cast<PolynomialFft<Complex<double>> *>(s_out);
}

template <>
template <>
__device__ inline void PolynomialFft<Complex<double>>::ifft<uint64_t>(
    Polynomial<uint64_t> *__restrict__ res,
    const PolynomialDegree &degree) const
{
    PolynomialDegree n_div_2 = PolynomialDegree{degree.val / 2};

    auto s_in = get_fft_scratch<Complex<double>>();

    BLOCK_COPY(s_in, this->coeffs(), n_div_2.val);

    // twisted_ifft operates in-place and returns s_in reinterpreted
    // as double*.
#ifdef FFT_NO_REORDER
    auto s_out = twisted_ifft_noreorder(s_in, degree.degree);
#else
    auto s_out = twisted_ifft(s_in, degree.val);
#endif

    inplace_reduce_mod_q_pow_2<double, 64>(
        s_out,
        degree.val);

    // Finally, we cast each value from double to uint64_t
    BLOCK_FOR_EACH(i, degree.val)
    {
        // The result is on the signed torus [-q/2, q/2). Cast to a signed integer
        // then bitcast back to unsigned to get back to [0, q).
        res->coeffs()[i] = (uint64_t)normalize_q_div_2_torus<double, uint64_t>(s_out[i]);
    }

    __syncthreads();
}

template <typename U>
__device__ inline Polynomial<U> *ifft_inplace(const PolynomialDegree &degree)
{
    auto s_out = twisted_ifft(s_in, degree.val);

    inplace_reduce_mod_q_pow_2<double, 64>(
        s_out,
        degree.val);

    auto s_out_uint = reinterpret_cast<Polynomial<uint64_t> *>(s_out);

    BLOCK_FOR_EACH(i, degree.val)
    {
        // The result is on the signed torus [-q/2, q/2). Cast to a signed integer
        // then bitcast back to unsigned to get back to [0, q).
        s_out_uint->coeffs()[i] = (uint64_t)normalize_q_div_2_torus<double, uint64_t>(s_out[i]);
    }

    return s_out_uint;
}
