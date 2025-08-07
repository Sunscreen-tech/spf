#pragma once

#include <cstdint>

#include "../../src/params.cuh"
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
    DstArray<GlweCiphertext<uint64_t>> *__restrict__ c,
    const DstArray<GlweCiphertext<uint64_t>> *__restrict__ a,
    const DstArray<GlweCiphertext<uint64_t>> *__restrict__ b)
{
    const auto params = GlweDef(LogPolyDegree(11), GlweSize(1));

    auto c_i = c->nth(blockIdx.x, params);
    auto a_i = a->nth(blockIdx.x, params);
    auto b_i = b->nth(blockIdx.x, params);

    glwe_add(c_i, a_i, b_i, params);
}

extern "C" __global__ void can_polynomial_glev_mad(
    DstArray<GlweCiphertextFft<Complex<double>>> *__restrict__ c,
    const DstArray<Polynomial<uint64_t>> *__restrict__ a,
    const DstArray<GlevCiphertextFft<Complex<double>>> *__restrict__ b,
    uint8_t *__restrict__ scratch_buffer
) {
    const auto& radix = PBS_RADIX_128;
    const auto& glwe = GLWE_1_128;
    auto scratch = PerBlockStackAllocator(scratch_buffer, get_scratch_size());

    auto c_i = c->nth(blockIdx.x, glwe);
    auto a_i = a->nth(blockIdx.x, glwe.polynomial_degree());
    auto b_i = b->nth(blockIdx.x, std::tuple(glwe, radix));

    decomposed_polynomial_glev_mad(c_i, a_i, b_i, glwe, radix, scratch);
}