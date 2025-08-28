#pragma once

#include "../math/primitives.cuh"
#include "../entities/lwe.cuh"
#include "../entities/glwe.cuh"
#include "../entities/bootstrap_key.cuh"
#include "../ops/homomorphisms.cuh"

__device__ inline u64 modulus_switch(u64 x, u32 log_chi, u32 log_v, u32 log_modulus) {
    u64 mask = (0x1 << log_modulus) - 1;
    x = x << log_chi;
    u32 shift_amount = 64 - (log_modulus - log_v);

    u64 round = (x >> (shift_amount - 1)) & 0x1;
    x = x >> shift_amount;

    return ((x + round) & mask) << log_v;
}

__device__ inline void generalized_programmable_bootstrap(
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

    // for (u32 i = 0; i < lwe_params.size.val; i++) {
    //     u64 a = input.a_b(i, lwe_params);
    //     a = modulus_switch(a, log_chi, log_v, glwe_params.log_poly_degree.val + 1);

    //     glwe_times_positive_monomial_negacyclic(*rotated_s, *output_s, static_cast<u32>(a), glwe_params);

    //     auto s = bsk.s(i, std::tuple(lwe_params, glwe_params, radix));

    //     destructive_cmux(*output_s, *rotated_s, s, glwe_params, radix, scratch);
    // }

    (*output_s).clone_into(output, glwe_params);
}