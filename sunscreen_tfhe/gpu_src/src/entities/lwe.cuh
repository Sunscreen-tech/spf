#pragma once

#include <cuda/std/complex>

#include "dst_array.cuh"
#include "polynomial.cuh"
#include "../math/math.cuh"
#include "../params.cuh"

class LweCiphertext
{
public:
    using BufTy = U64Buf;

    LweCiphertext() = delete;
    __device__ explicit constexpr inline LweCiphertext(BufTy data): m_data(data) { }

    __device__ static constexpr inline u32 size(const LweDef &params)
    {
        return params.size.val + 1;
    }

    __device__ constexpr inline u64 a_b(u32 i, const LweDef &glwe) const
    {
        return m_data.get_u64(i);
    }

    __device__ static constexpr inline LweCiphertext from_ptr(BufTy::BasePtrTy *ptr) {
        return LweCiphertext(BufTy::from_ptr(ptr));
    }

    __device__ static constexpr inline const LweCiphertext from_ptr(const BufTy::BasePtrTy *ptr) {
        return LweCiphertext(BufTy::from_ptr(ptr));
    }

private:
    BufTy m_data;
};
