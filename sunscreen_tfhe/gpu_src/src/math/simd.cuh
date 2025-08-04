#pragma once
#include <bit>

#include <cstdint>
#include "../iter_tools.cuh"

template <uint64_t LOG2_Q>
constexpr __device__ double q_as_float()
{
    uint64_t exp = 1023 + LOG2_Q;

    return std::bit_cast<double>(exp << 52);
}

/// Reduce each value in `s_inout` by `2**LOG2_Q` and emit the results as type `U`.
/// This method runs in-place and returns the pointer to the input data recast as
/// a `U*`.
template <typename T, uint64_t LOG2_Q>
__device__ void inplace_reduce_mod_q_pow_2(
    T* __restrict__ s_inout,
    const uint32_t n)
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
        rem = rem <= -q_div2
                  ? rem_plus_q
                  : rem;

        s_inout[i] = rem;
    }
}