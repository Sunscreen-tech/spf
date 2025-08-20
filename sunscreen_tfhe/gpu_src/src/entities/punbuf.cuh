#pragma once
#include <complex>
#include <bit>

#include "../math/primitives.cuh"

/// @brief Type punning is a notoriously hard thing to do in C++ in a standards
/// compliant manner, but is unfortunately very useful in minimizing memory
/// (in particular, shared memory) usage. For example, we need to compute
/// negacyclic polynomial convolutions of uint64_t values, which involves
/// ideally in-place FFTs. This requires converting from uint64_t* to double* to 
/// complex<double>*, which is undefined behavior if you use reinterpret_cast.
///
/// Enter PunBuf, which exploits std::complex's array-oriented access property
/// to allow accessing the same buffer as std::complex<double>* or double*.
/// Furthermore, we provide getters and setters for loading/storing {u}int64_t
/// values in the the buffer via std::bit_cast.
///
/// These encompass all the interesting primitive data types in TFHE.
///
/// See https://youtu.be/_qzMpk-22cc?si=cfpqDUTVE1FL5XdM&t=3091
/// and https://en.cppreference.com/w/cpp/numeric/complex.html for more info.
class PunBuf {
public:
    PunBuf() = delete;
    __device__ explicit constexpr inline PunBuf(std::complex<f64>* data): m_data(data) { }

    __device__ constexpr inline f64 *as_f64() {
        // Explicitly 
        return reinterpret_cast<f64 *>(m_data);
    }
    __device__ constexpr inline const f64 *as_f64() const { return reinterpret_cast<const f64 *>(m_data); }

    __device__ constexpr inline std::complex<f64> *as_complex() { return m_data; }
    __device__ constexpr inline const std::complex<f64> *as_complex() const { return m_data; }

    __device__ constexpr inline u64 get_u64(const u32 i) const { return std::bit_cast<u64>(as_f64()[i]); }
    __device__ constexpr inline void set_u64(const u32 i, u64 val) { as_f64()[i] = std::bit_cast<f64>(val); }
    
    __device__ constexpr inline u64 get_i64(const u32 i) const { return std::bit_cast<u64>(as_f64()[i]); }
    __device__ constexpr inline void set_i64(const u32 i, i64 val) { as_f64()[i] = std::bit_cast<f64>(val); }

    /// Creates a new PunBuf at &as_complex()[i].
    ///
    /// Unfortunately, this introduces a limitation that underlying buffers must be
    /// a multiple of 2 in length.
    __device__ constexpr inline PunBuf split(u32 i) {
        return PunBuf(&as_complex()[i]);
    }

    /// Creates a new const PunBuf at &as_complex()[i].
    ///
    /// Unfortunately, this introduces a limitation that underlying buffers must be
    /// a multiple of 2 in length.
    __device__ constexpr inline const PunBuf split(u32 i) const {
        // Const-ness immediately comes back 
        return PunBuf(const_cast<std::complex<f64> *>(&as_complex()[i]));
    }

    __device__ static constexpr inline PunBuf from_ptr(std::complex<f64>* data) {
        return PunBuf(data);
    }

    __device__ static constexpr inline const PunBuf from_ptr(const std::complex<f64>* data) {
        return PunBuf(const_cast<std::complex<f64>*>(data));
    }
private:
    std::complex<f64> *m_data;
};