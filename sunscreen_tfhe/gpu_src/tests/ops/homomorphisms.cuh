#pragma once

#include <cstdint>

#include "../../src/entities/dst_array.cuh"
#include "../../src/entities/glwe.cuh"
#include "../../src/ops/homomorphisms.cuh"

extern "C" __global__ void can_glwe_sub(
    DstArray<GlweCiphertext<uint64_t>> *c,
    const DstArray<GlweCiphertext<uint64_t>> *a,
    const DstArray<GlweCiphertext<uint64_t>> *b)
{
    const auto params = GlweDef(LogPolyDegree(11), GlweSize(1));

    auto c_i = c->nth(blockIdx.x, params);
    auto a_i = a->nth(blockIdx.x, params);
    auto b_i = b->nth(blockIdx.x, params);

    glwe_sub(c_i, a_i, b_i, params);
}

extern "C" __global__ void can_glwe_add(
    DstArray<GlweCiphertext<uint64_t>> *c,
    const DstArray<GlweCiphertext<uint64_t>> *a,
    const DstArray<GlweCiphertext<uint64_t>> *b)
{
    const auto params = GlweDef(LogPolyDegree(11), GlweSize(1));

    auto c_i = c->nth(blockIdx.x, params);
    auto a_i = a->nth(blockIdx.x, params);
    auto b_i = b->nth(blockIdx.x, params);

    glwe_add(c_i, a_i, b_i, params);
}