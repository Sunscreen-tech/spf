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
    const auto params = GLWE_1_2048_128;

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
    const auto params = GLWE_1_2048_128;

    auto c_i = c->nth(blockIdx.x, params);
    auto a_i = a->nth(blockIdx.x, params);
    auto b_i = b->nth(blockIdx.x, params);

    glwe_add(c_i, a_i, b_i, params);
}

extern "C" __global__ void can_glwe_polynomial_mad(
    DstArray<GlweCiphertextFft<Complex<double>>> *__restrict__ c,
    const DstArray<GlweCiphertextFft<Complex<double>>> *__restrict__ a,
    const DstArray<PolynomialFft<Complex<double>>> *__restrict__ b)
{
    const auto &glwe = GLWE_1_2048_128;

    auto c_i = c->nth(blockIdx.x, glwe);
    auto a_i = a->nth(blockIdx.x, glwe);
    auto b_i = b->nth(blockIdx.x, glwe.polynomial_degree());

    glwe_polynomial_mad(c_i, a_i, b_i, glwe);
}

extern "C" __global__ void can_polynomial_glev_mad(
    DstArray<GlweCiphertextFft<Complex<double>>> *__restrict__ c,
    const DstArray<Polynomial<uint64_t>> *__restrict__ a,
    const DstArray<GlevCiphertextFft<Complex<double>>> *__restrict__ b,
    uint8_t *__restrict__ scratch_buffer)
{
    const auto &radix = PBS_RADIX_2_16_128;
    const auto &glwe = GLWE_1_2048_128;
    auto scratch = PerBlockStackAllocator(scratch_buffer, get_scratch_size());

    auto c_i = c->nth(blockIdx.x, glwe);
    auto a_i = a->nth(blockIdx.x, glwe.polynomial_degree());
    auto b_i = b->nth(blockIdx.x, std::tuple(glwe, radix));

    // printf("%le\n", c_i->a_b(0, glwe)->coeffs()[threadIdx.x].re());
    //printf("%le\n", b_i->decomps(0, std::tuple(glwe, radix))->a_b(0, glwe)->coeffs()[threadIdx.x].re());

    decomposed_polynomial_glev_mad(c_i, a_i, b_i, glwe, radix, scratch);
}