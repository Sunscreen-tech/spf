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