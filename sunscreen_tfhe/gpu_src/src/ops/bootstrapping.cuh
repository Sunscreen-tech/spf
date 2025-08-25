#pragma once

#include "../math/primitives.cuh"
#include "../entities/lwe.cuh"
#include "../entities/glwe.cuh"
#include "../entities/bootstrap_key.cuh"

__device__ inline u64 modulus_switch(u64 x, u32 log_chi, u32 log_v, u32 log_modulus) {
    u64 mask = (0x1 << log_modulus) - 1;
    u64 x = x << log_chi;
    u32 shift_amount = 64 - (log_modulus - log_v);

    u64 round = (x >> (shift_amount - 1)) & 0x1;
    x = x >> shift_amount;

    return (x + round) & mask << log_v;
}

__device__ inline void generalized_programmable_bootstrap(
    GlweCiphertext output,
    const LweCiphertext input,
    const GlweCiphertext lut,
    const BootstrapKeyFft bsk,
    u32 log_chi,
    u32 log_v,
    const LweDef &lwe_params,
    const GlweDef &glwe_params,
    const RadixDecomposition &radix
) {

}