#pragma once
#include <cuda/std/complex>

#include "punbuf.cuh"
#include "../math/primitives.cuh"

/// @brief An array of DSTs with methods for retrieving inner DSTs.
/// @tparam T The item type
template <typename T>
class DstArray {
public:
    using BufTy = typename T::BufTy;

    DstArray() = delete;
    __device__ explicit constexpr inline DstArray(BufTy data): m_data(data) { }

    template <typename V>
    __device__ constexpr inline T nth(u32 i, const V& size_info) {
        return T(m_data.split(T::size(size_info) * i));
    }

    template <typename V>
    __device__ constexpr inline const T nth(u32 i, const V& size_info) const {
        return T(m_data.split(T::size(size_info) * i));
    }

    __device__ static constexpr inline DstArray<T> from_ptr(BufTy::BasePtrTy *ptr) {
        return DstArray(BufTy::from_ptr(ptr));
    }

    __device__ static constexpr inline const DstArray<T> from_ptr(const BufTy::BasePtrTy *ptr) {
        return DstArray(BufTy::from_ptr(ptr));
    }
private:
    BufTy m_data;
};
