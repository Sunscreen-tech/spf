#pragma once
#include <cstdint>

#include "../math/math.cuh"
#include "../params.cuh"
#include "../math/simd.cuh"
#include "../math/fft/negacyclic.cuh"
#include "../iter_tools.cuh"
#include "../features.cuh"

class PolynomialFft;

class Polynomial
{
public:
    Polynomial() = delete;
    __device__ explicit constexpr inline Polynomial(PunBuf data): m_data(data) { }

    __device__ static constexpr inline uint32_t size(const PolynomialDegree &size_info)
    {
        // Assumption that polynomial degree is a power of 2.
        return size_info.val / 2;
    }

    __device__ constexpr inline PunBuf coeffs()
    {
        return m_data;
    }

    __device__ constexpr inline const PunBuf coeffs() const
    {
        return m_data;
    }

    __device__ inline void fft(PolynomialFft res, const PolynomialDegree &degree) const;

    __device__ inline PolynomialFft fft_inplace(const PolynomialDegree &degree);

    __device__ static constexpr inline Polynomial from_ptr(std::complex<f64> *ptr) {
        return Polynomial(PunBuf::from_ptr(ptr));
    }

    __device__ static constexpr inline const Polynomial from_ptr(const std::complex<f64> *ptr) {
        return Polynomial(PunBuf::from_ptr(ptr));
    }

    /*
    __device__ inline void clone_into(Polynomial<T> *other, const PolynomialDegree &degree) const
    {
        BLOCK_COPY(other->coeffs(), this->coeffs(), degree.val);
    }*/

private:
    PunBuf m_data;
};

class PolynomialFft
{
public:
    PolynomialFft() = delete;
    __device__ explicit constexpr inline PolynomialFft(PunBuf data): m_data(data) { }

    __device__ static inline uint32_t size(const PolynomialDegree &size_info)
    {
        // Assumption that polynomial degree is a power of 2.
        return size_info.val / 2;
    }

    __device__ constexpr inline PunBuf coeffs()
    {
        return m_data;
    }

    __device__ constexpr inline const PunBuf coeffs() const
    {
        return m_data;
    }

    __device__ static constexpr inline PolynomialFft from_ptr(std::complex<f64> *ptr) {
        return PolynomialFft(PunBuf::from_ptr(ptr));
    }

    __device__ static constexpr inline const PolynomialFft from_ptr(const std::complex<f64> *ptr) {
        return PolynomialFft(PunBuf::from_ptr(ptr));
    }

    __device__ inline void ifft(Polynomial res, const PolynomialDegree &degree) const;

    __device__ inline Polynomial ifft_inplace(const PolynomialDegree &degree);

private:
    PunBuf m_data;
};

__device__ inline void Polynomial::fft(
    PolynomialFft res,
    const PolynomialDegree &degree) const
{
    /*
    auto s_in = get_fft_scratch<double>();

    // Reinterpret our [0, q) torus as [-q/2, q/2) to minimize errors. In particular,
    // this ensures that small negative torus elements don't blow up into large FFTs
    // that fail to modulo reduce.
    BLOCK_FOR_EACH(i, degree.val)
    {
        s_in[i] = unsigned_to_signed_torus<double, uint64_t>(this->coeffs()[i]);
    }

    // twisted_fft operated in-place and returns s_in reinterpreted
    // as Complex<double>*
#ifdef FFT_NO_REORDER
    auto s_out = twisted_fft_noreorder(s_in, degree.val);
#else
    auto s_out = twisted_fft(s_in, degree.val);
#endif

    BLOCK_COPY(res->coeffs(), s_out, degree.val / 2);*/
}

__device__ inline void PolynomialFft::ifft(
    Polynomial res,
    const PolynomialDegree &degree) const
{
    /*
    PolynomialDegree n_div_2 = PolynomialDegree{degree.val / 2};

    auto s_in = get_fft_scratch<Complex<double>>();

    BLOCK_COPY(s_in, this->coeffs(), n_div_2.val);

    // twisted_ifft operates in-place and returns s_in reinterpreted
    // as double*.
#ifdef FFT_NO_REORDER
    auto s_out = twisted_ifft_noreorder(s_in, degree.val);
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
        res->coeffs()[i] = (uint64_t)signed_to_unsigned_torus<double, uint64_t>(s_out[i]);
    }

    __syncthreads();*/
}

/*
template <>
template <>
__device__ inline PolynomialFft<Complex<double>> *Polynomial<uint64_t>::fft_inplace(const PolynomialDegree &degree)
{
    auto s_cast = reinterpret_cast<double *>(this->coeffs());

    // Reinterpret our [0, q) torus as [-q/2, q/2) to minimize errors. In particular,
    // this ensures that small negative torus elements don't blow up into large FFTs
    // that fail to modulo reduce.
    BLOCK_FOR_EACH(i, degree.val)
    {
        s_cast[i] = unsigned_to_signed_torus<double, uint64_t>(this->coeffs()[i]);
    }

    __syncthreads();

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
    auto s_out = twisted_ifft_noreorder(s_in, degree.val);
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
        res->coeffs()[i] = (uint64_t)signed_to_unsigned_torus<double, uint64_t>(s_out[i]);
    }

    __syncthreads();
}

template <>
template <>
__device__ inline Polynomial<uint64_t> *PolynomialFft<Complex<double>>::ifft_inplace(const PolynomialDegree &degree)
{
    auto s_in = reinterpret_cast<Complex<double> *>(this);
    auto s_out = twisted_ifft(s_in, degree.val);

    inplace_reduce_mod_q_pow_2<double, 64>(
        s_out,
        degree.val);

    auto s_out_uint = reinterpret_cast<Polynomial<uint64_t> *>(s_out);

    BLOCK_FOR_EACH(i, degree.val)
    {
        // The result is on the signed torus [-q/2, q/2). Cast to a signed integer
        // then bitcast back to unsigned to get back to [0, q).
        s_out_uint->coeffs()[i] = (uint64_t)signed_to_unsigned_torus<double, uint64_t>(s_out[i]);
    }

    return s_out_uint;
}
*/