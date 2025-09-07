#pragma once

#include "../features.cuh"

#ifndef THREAD_BLOCK_CLUSTERS
#error "This feature requires compute capability 9.0 or later"
#endif

#include "../entities/lwe.cuh"
#include "../entities/glwe.cuh"
#include "../entities/bootstrap_key.cuh"
#include "../params.cuh"
#include "bootstrapping.cuh"
#include "parallel_homomorphisms.cuh"

__device__ inline void parallel_generalized_programmable_bootstrap(
    GlweCiphertext output,
    const LweCiphertext input,
    const GlweCiphertext lut,
    const BootstrapKeyFft bsk,
    const u32 log_chi,
    const u32 log_v,
    const LweDef &lwe_params,
    const GlweDef &glwe_params,
    const RadixDecomposition &radix,
    PerBlockStackAllocator &scratch
) {
    // Under standard parameters, this requires
    // sizeof(double) * 2048 * 2 * 2 = 64kB.
    auto output_s = scratch.alloc<GlweCiphertext>(glwe_params);
    auto rotated_s = scratch.alloc<GlweCiphertext>(glwe_params);
    
    u64 b = input.a_b(lwe_params.size.val, lwe_params);

    // We're evaluating negacyclically over 2N. Hence, log2(d) + 1.
    auto b_mod_switched = modulus_switch(b, log_chi, log_v, glwe_params.log_poly_degree.val + 1);

    glwe_times_negative_monomial_negacyclic(*output_s, lut, static_cast<u32>(b_mod_switched), glwe_params);

    for (u32 i = 0; i < lwe_params.size.val; i++) {
        u64 a = input.a_b(i, lwe_params);
        a = modulus_switch(a, log_chi, log_v, glwe_params.log_poly_degree.val + 1);

        glwe_times_positive_monomial_negacyclic(*rotated_s, *output_s, static_cast<u32>(a), glwe_params);

        auto s = bsk.s(i, cuda::std::tuple(lwe_params, glwe_params, radix));

        parallel_destructive_cmux(*output_s, *rotated_s, s, glwe_params, radix, scratch);
    }

    (*output_s).clone_into(output, glwe_params);
}