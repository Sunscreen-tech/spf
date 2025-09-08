#pragma once

#include "../../src/features.cuh"

#ifndef THREAD_BLOCK_CLUSTERS
#error NO_THREAD_BLOCK_CLUSTERS_ERR
#endif

#include <cooperative_groups.h>

#include "../../src/entities/dst_array.cuh"
#include "../../src/entities/glwe.cuh"
#include "../../src/ops/parallel_homomorphisms.cuh"

namespace cg = cooperative_groups;

template <typename Dim>
__device__ void reduce_case(
    DstArray<GlweCiphertext> output,
    const DstArray<GlweCiphertext> input
) {
    auto cluster = cg::this_cluster();
    auto glwe = GLWE_1_2048_128;
    auto scratch = get_shared_allocator(64 * 1024);
    auto glwe_s = scratch.alloc<GlweCiphertext>(glwe);

    auto input_i = input.nth(DimUtils<Dim>::extract(blockIdx), glwe);

    auto out_idx = DimUtils<Dim>::extract(blockIdx) / DimUtils<Dim>::extract(cluster.dim_blocks());
    auto output_i = output.nth(out_idx, glwe);

    input_i.clone_into(*glwe_s, glwe);
    auto glwe_fft_s = std::move(*glwe_s).fft_inplace(glwe);

    reduce_glwe_fft<Dim>(glwe_fft_s, glwe);

    if (cluster.block_rank() == 0) {
        glwe_fft_s.ifft(output_i, glwe, scratch);
    }
}

extern "C" __global__ void can_reduce_glwe_fft_dim_x(
    DstArray<GlweCiphertext> output,
    const DstArray<GlweCiphertext> input
) {
    reduce_case<DimX>(output, input);
}

extern "C" __global__ void can_reduce_glwe_fft_dim_y(
    DstArray<GlweCiphertext> output,
    const DstArray<GlweCiphertext> input
) {
    reduce_case<DimY>(output, input);
}

extern "C" __global__ void can_parallel_polynomial_glev_mad(
    DstArray<GlweCiphertext> c,
    const DstArray<Polynomial> a,
    const DstArray<GlevCiphertext> b,
    cuda::std::complex<f64> *__restrict__ scratch_buffer)
{
    auto scratch_s = get_shared_allocator(96 * 1024);

    const auto &radix = PBS_RADIX_2_16_128;
    const auto &glwe = GLWE_1_2048_128;
    auto scratch_g = PerBlockStackAllocator(scratch_buffer, get_scratch_size());

    auto c_i = c.nth(blockIdx.x, glwe);
    auto a_i = a.nth(blockIdx.x, glwe.polynomial_degree());
    auto b_i = b.nth(blockIdx.x, cuda::std::tuple(glwe, radix));

    auto c_i_fft = scratch_s.alloc<GlweCiphertextFft>(glwe);
    auto a_s  = scratch_s.alloc<Polynomial>(glwe.polynomial_degree());
    auto b_i_fft = scratch_g.alloc<GlevCiphertextFft>(cuda::std::tuple(glwe, radix));

    c_i.fft(*c_i_fft, glwe, scratch_s);
    b_i.fft(*b_i_fft, cuda::std::tuple(glwe, radix), scratch_s);

    parallel_decomposed_polynomial_glev_mad(*c_i_fft, a_i, *b_i_fft, glwe, radix, scratch_g);

    (*c_i_fft).ifft(c_i, glwe, scratch_s);
}

extern "C" __global__ void can_parallel_destructive_cmux(
    DstArray<GlweCiphertext> a,
    DstArray<GlweCiphertext> b,
    const DstArray<GgswCiphertext> sel,
    cuda::std::complex<f64> *__restrict__ scratch_buffer)
{
    auto scratch_s = get_shared_allocator(128 * 1024 / sizeof(cuda::std::complex<f64>));

    const auto &radix = PBS_RADIX_2_16_128;
    const auto &glwe = GLWE_1_2048_128;
    auto scratch = PerBlockStackAllocator(scratch_buffer, get_scratch_size());

    auto a_i = a.nth(blockIdx.x, glwe);
    auto b_i = b.nth(blockIdx.x, glwe);
    auto sel_i = sel.nth(blockIdx.x, cuda::std::tuple(glwe, radix));
    
    auto sel_i_fft = scratch.alloc<GgswCiphertextFft>(cuda::std::tuple(glwe, radix));
    sel_i.fft(*sel_i_fft, cuda::std::tuple(glwe, radix), scratch_s);

    auto a_s = scratch_s.alloc<GlweCiphertext>(glwe);
    auto b_s = scratch_s.alloc<GlweCiphertext>(glwe);

    a_i.clone_into(*a_s, glwe);
    b_i.clone_into(*b_s, glwe);

    parallel_destructive_cmux(*a_s, *b_s, *sel_i_fft, glwe, radix, scratch_s);
}