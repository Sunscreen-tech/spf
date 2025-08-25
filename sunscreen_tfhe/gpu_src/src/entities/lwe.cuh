#pragma once

#include <cuda/std/complex>
#include <cstdint>

#include "dst_array.cuh"
#include "polynomial.cuh"
#include "../math/math.cuh"
#include "../params.cuh"

class LweCiphertext
{
public:
    LweCiphertext() = delete;
    __device__ explicit constexpr inline LweCiphertext(PunBuf data): m_data(data) { }

    __device__ static constexpr inline u32 size(const LweDef &params)
    {
        // LWEs use u64 values, which are half as wide as a complex.
        u32 complex_count = params.size.val / 2;

        // Round up when len(a) + 1 is odd
        if (params.size.val % 2 == 0) {
            complex_count = params.size.val / 2 + 1;
        }

        return complex_count;
    }

    __device__ constexpr inline const u64 a_b(u32 i, const LweDef &glwe) const
    {
        return m_data.get_u64(i);
    }

    __device__ static constexpr inline LweCiphertext from_ptr(cuda::std::complex<double> *ptr) {
        return LweCiphertext(PunBuf::from_ptr(ptr));
    }

    __device__ static constexpr inline const LweCiphertext from_ptr(const cuda::std::complex<double> *ptr) {
        return LweCiphertext(PunBuf::from_ptr(ptr));
    }

private:
    PunBuf m_data;
};