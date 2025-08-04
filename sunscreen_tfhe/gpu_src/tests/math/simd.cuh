#pragma once
#include <cstdint>

#include "../../src/math/simd.cuh"

extern "C" __global__ void can_reduce_mod_2_pow_64(
    double *__restrict__ input,
    uint32_t n
) {
    inplace_reduce_mod_q_pow_2<double, 64>(input, n);
}