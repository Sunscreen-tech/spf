#pragma once

#include "math.cuh"
#include "../iter_tools.cuh"

/// @brief  Converts a value on the floating point (`F`) torus [-q/2, q/2] to an unsigned
/// integer (`U`) on the torus [0, q).
/// @param x The double torus value
/// @return The unsigned torus value.
template <typename F, typename U>
__device__ inline U signed_to_unsigned_torus(F x) {
    using SignedTy = typename Unsigned<U>::SignedTy;

    return static_cast<U>((SignedTy)x);
}

/// @brief  Converts a value on the unsigned (`U`) torus [0, q) to an a signed
/// float (`F`) on the torus [-q/2, q/2).
/// @param x The double torus value
/// @return The unsigned torus value.
template <typename F, typename U>
__device__ inline F unsigned_to_signed_torus(U x) {
    using SignedTy = typename Unsigned<U>::SignedTy;

    return static_cast<F>((SignedTy)x);
}

template <uint64_t LOG2_Q>
constexpr __device__ double q_as_float()
{
    u64 exp = 1023 + LOG2_Q;

    return __longlong_as_double(static_cast<i64>(exp << 52));
}

/// Reduce each value in `s_inout` by `2**LOG2_Q` and emit the results as type `U`.
/// This method runs in-place and returns the pointer to the input data recast as
/// a `U*`.
template <typename T, uint64_t LOG2_Q>
__device__ void inplace_reduce_mod_q_pow_2(
    T* __restrict__ s_inout,
    const u32 n)
{
    T q = q_as_float<LOG2_Q>();
    T q_div2 = q_as_float<LOG2_Q - 1>();

    BLOCK_FOR_EACH(i, n)
    {
        T val = s_inout[i];

        // Reduce mod_q, exploiting the fact that q is a power of 2.
        T rem = trunc(-(val / q)) * q + val;

        // Normalize results to be within [-q/2, q/2). This results in less rounding
        // error when converting back to the torus.
        // Pretty please emit conditional movs to avoid branch divergence :)
        T rem_min_q = rem - q;
        T rem_plus_q = rem + q;

        rem = rem >= q_div2
                  ? rem_min_q
                  : rem;

        // If previous was true, this can't be.
        rem = rem < -q_div2
                  ? rem_plus_q
                  : rem;

        s_inout[i] = rem;
    }
}