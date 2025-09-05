#pragma once

// Methods in here use cooperative groups.
#if __CUDA_ARCH__ < 900
#error "This feature requires compute capability 9.0 or later"
#endif

#include <cooperative_groups.h>
#include "../entities/glwe.cuh"
#include "../entities/ggsw.cuh"
#include "../params.cuh"
#include "homomorphisms.cuh"

namespace cg = cooperative_groups;

__device__ inline void reduce_glwe_fft(
    GlweCiphertextFft c, // Must reside in shared memory
    const GlweDef &glwe,
    const u32 rank,
    const u32 num_
) {
    auto cluster = cg::this_cluster();

}

__device__ inline void parallel_decomposed_polynomial_glev_mad(
    GlweCiphertextFft c,
    const Polynomial a,
    const GlevCiphertextFft b,
    const GlweDef &glwe,
    const RadixDecomposition &radix,
    PerBlockStackAllocator &scratch)
{
    auto cluster = cg::this_cluster();

    // Under standard parameters, we allocate another 32kB of memory.
    auto decomp_scratch = scratch.alloc<Polynomial>(glwe.polynomial_degree());
    auto decomp = PolynomialSignedRadixDecomposer(a, *decomp_scratch, radix, glwe.polynomial_degree());
    auto decomp_poly = scratch.alloc<Polynomial>(glwe.polynomial_degree());

    for (u32 i = 0; i < radix.count.val; i++)
    {
        u32 l = radix.count.val - i - 1;

        auto b_l = b.decomps(l, cuda::std::tuple(glwe, radix));
        decomp.next(*decomp_poly);

        // Only compute what our block is responsible for.
        if (i % cluster.dim_blocks().x == cluster.block_index().x) {
            auto decomp_poly_fft = std::move(*decomp_poly).fft_inplace(glwe.polynomial_degree());

            glwe_polynomial_mad(c, b_l, decomp_poly_fft, glwe);

            // Ensure the previous decomposition is done being used before computing the next one.
            __syncthreads();
        }
    }

    cluster.sync();
    // Reduce c_fft across all our groups.
    if (cluster.block_index().x == 0) {
        for (u32 i = 1; i < radix.count.val; i++) {
            // Get a pointer to the GLWE ciphertext for the remote group
        }
    }
}

/// @brief Compute a parallel glwe_ggsw multiply-add using cooperative groups.
/// @param c_fft Must be an allocation in `scratch` (i.e. block-local)
/// @param a
/// @param b
/// @param glwe
/// @param radix
/// @param scratch
/// @return
__device__ inline void parallel_glwe_ggsw_mad(
    GlweCiphertextFft c_fft,
    const GlweCiphertext a,
    const GgswCiphertextFft b,
    const GlweDef &glwe,
    const RadixDecomposition &radix,
    PerBlockStackAllocator &scratch)
{
    auto cluster = cg::this_cluster();

    // Divide c_fft by the number of cooperative groups. We do this because it will get
    // redundantly summed by each group in parallel.
    if (cluster.num_blocks() > 1)
    {
        double g_inv = 1.0 / static_cast<double>(cluster.num_blocks());

        glwe_mul_scalar_inplace(c_fft, g_inv, glwe);

        __syncthreads();
    }

    // The y-dimension of the cluster index is which row of the glwe-glev outer product
    // we're computing. This is the "map" step that computes each cluster group
    for (u32 i = cluster.block_index().y; i <= glwe.size.val; i += cluster.dim_blocks().y)
    {
        auto a_i = a.a_b(i, glwe);
        auto glev_i = b.rows(i, cuda::std::tuple(glwe, radix));

        parallel_decomposed_polynomial_glev_mad(c_fft, a_i, glev_i, glwe, radix, scratch);
    }
}

/// @brief Same as `destructive_cmux`, but uses cooperative groups to reduce latency.
///
/// Ideally, this is launched in a (k + 1) x \ell cluster to properly load balance work.
__device__ inline void parallel_destructive_cmux(
    GlweCiphertext a,
    GlweCiphertext b,
    const GgswCiphertextFft sel,
    const GlweDef &glwe,
    const RadixDecomposition &radix,
    PerBlockStackAllocator &scratch)
{
    // b -= a
    glwe_sub_assign(b, a, glwe);

    auto a_fft = std::move(a).fft_inplace(glwe);

    // a += (b - a) * sel
    glwe_ggsw_mad(a_fft, b, sel, glwe, radix, scratch);

    std::move(a_fft).ifft_inplace(glwe);
}
