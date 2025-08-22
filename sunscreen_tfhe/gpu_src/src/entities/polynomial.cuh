#pragma once
#include <cuda/std/complex>
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

    __device__ static constexpr inline u32 size(const PolynomialDegree &size_info)
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

    __device__ inline PolynomialFft fft_inplace(const PolynomialDegree &degree) &&;

    __device__ static constexpr inline Polynomial from_ptr(cuda::std::complex<f64> *ptr) {
        return Polynomial(PunBuf::from_ptr(ptr));
    }

    __device__ static constexpr inline const Polynomial from_ptr(const cuda::std::complex<f64> *ptr) {
        return Polynomial(PunBuf::from_ptr(ptr));
    }

    __device__ inline void clone_into(Polynomial other, const PolynomialDegree &degree) const
    {
        BLOCK_COPY(other.coeffs().as_f64(), this->coeffs().as_f64(), degree.val);
    }

private:
    PunBuf m_data;
};

class PolynomialFft
{
public:
    PolynomialFft() = delete;
    __device__ explicit constexpr inline PolynomialFft(PunBuf data): m_data(data) { }

    __device__ static inline u32 size(const PolynomialDegree &size_info)
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

    __device__ static constexpr inline PolynomialFft from_ptr(cuda::std::complex<f64> *ptr) {
        return PolynomialFft(PunBuf::from_ptr(ptr));
    }

    __device__ static constexpr inline const PolynomialFft from_ptr(const cuda::std::complex<f64> *ptr) {
        return PolynomialFft(PunBuf::from_ptr(ptr));
    }

    __device__ inline void ifft(Polynomial res, const PolynomialDegree &degree) const;

    /// @brief Consume the the current Polynomial and return its FFT.
    /// @param degree 
    /// @return The FFT'd polynomial
    __device__ inline Polynomial ifft_inplace(const PolynomialDegree &degree) &&;

    __device__ inline void clone_into(PolynomialFft other, const PolynomialDegree &degree) const
    {
        BLOCK_COPY(other.coeffs().as_complex(), this->coeffs().as_complex(), degree.val / 2);
    }
private:
    PunBuf m_data;
};

__device__ inline void Polynomial::fft(
    PolynomialFft res,
    const PolynomialDegree &degree) const
{
    auto scratch = get_fft_scratch();

    // Reinterpret our [0, q) torus as [-q/2, q/2) to minimize errors. In particular,
    // this ensures that small negative torus elements don't blow up into large FFTs
    // that fail to modulo reduce.
    BLOCK_FOR_EACH(i, degree.val)
    {
        scratch.as_f64()[i] = static_cast<f64>(this->coeffs().get_i64(i));
    }

    // twisted_fft operated in-place and returns s_in reinterpreted
    // as Complex<double>*
    twisted_fft_noreorder(scratch, degree.val);

    BLOCK_COPY(res.coeffs().as_complex(), scratch.as_complex(), degree.val / 2);
}

__device__ inline void PolynomialFft::ifft(
    Polynomial res,
    const PolynomialDegree &degree) const
{
    PolynomialDegree n_div_2 = PolynomialDegree{degree.val / 2};

    auto scratch = get_fft_scratch();

    BLOCK_COPY(scratch.as_complex(), this->coeffs().as_complex(), n_div_2.val);

    // twisted_ifft operates in-place and returns s_in reinterpreted
    // as double*.
    twisted_ifft_noreorder(scratch, degree.val);

    inplace_reduce_mod_q_pow_2<double, 64>(
        scratch.as_f64(),
        degree.val);

    // Finally, we cast each value from double to uint64_t
    BLOCK_FOR_EACH(i, degree.val)
    {
        // The result is on the signed torus [-q/2, q/2). Cast to a signed integer
        // then bitcast back to unsigned to get back to [0, q).
        res.coeffs().set_i64(i, static_cast<i64>(scratch.as_f64()[i]));
    }
}

__device__ inline PolynomialFft Polynomial::fft_inplace(const PolynomialDegree &degree) &&
{
    // Reinterpret our [0, q) torus as [-q/2, q/2) to minimize errors. In particular,
    // this ensures that small negative torus elements don't blow up into large FFTs
    // that fail to modulo reduce.
    BLOCK_FOR_EACH(i, degree.val)
    {
        this->coeffs().as_f64()[i] = static_cast<f64>(this->coeffs().get_i64(i));
    }

    twisted_fft_noreorder(this->coeffs(), degree.val);

    return PolynomialFft(this->coeffs());
}

__device__ inline Polynomial PolynomialFft::ifft_inplace(const PolynomialDegree &degree) &&
{
    twisted_ifft_noreorder(this->coeffs(), degree.val);

    inplace_reduce_mod_q_pow_2<double, 64>(
        this->coeffs().as_f64(),
        degree.val);

    BLOCK_FOR_EACH(i, degree.val)
    {
        // The result is on the signed torus [-q/2, q/2). Cast to a signed integer
        // then bitcast back to unsigned to get back to [0, q).
        this->coeffs().set_i64(i, static_cast<i64>(this->coeffs().as_f64()[i]));
    }

    return Polynomial(this->coeffs());
}
