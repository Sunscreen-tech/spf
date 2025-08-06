#pragma once
#include <cstdint>

#include "../../src/iter_tools.cuh"
#include "../../src/math/simd.cuh"

extern "C" __global__ void can_reduce_mod_2_pow_64(
    double *__restrict__ input,
    uint64_t *__restrict__ output,
    uint32_t n)
{
    inplace_reduce_mod_q_pow_2<double, 64>(input, n);

    BLOCK_FOR_EACH(i, n)
    {
        output[i] = normalize_q_div_2_torus<double, uint64_t>(input[i]);
    }
}