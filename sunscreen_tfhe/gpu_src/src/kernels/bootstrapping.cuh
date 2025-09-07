#pragma once

#include "../entities/dst_array.cuh"
#include "../ops/bootstrapping.cuh"
#include "../features.cuh"

extern "C" __global__ void kernel_generalized_functional_bootstrap(
    cuda::std::complex<f64> *__restrict__ output_buf,
    const u64 *__restrict__ input_buf,
    const cuda::std::complex<f64> *__restrict__ lut_buf,
    const cuda::std::complex<f64> *__restrict__ bsk_buf,
    const u32 log_chi,
    const u32 log_v,
    const LweDef lwe_params,
    const GlweDef glwe_params,
    const RadixDecomposition radix,
    u32 local_storage_amount)
{
    // TODO, size-aware with local storage.
    auto scratch = get_shared_allocator(local_storage_amount);

    auto output = DstArray<GlweCiphertext>::from_ptr(output_buf);
    auto input = DstArray<LweCiphertext>::from_ptr(input_buf);
    auto lut = GlweCiphertext::from_ptr(lut_buf);
    auto bsk = BootstrapKeyFft::from_ptr(bsk_buf);

    generalized_programmable_bootstrap(
        output.nth(blockIdx.x, glwe_params),
        input.nth(blockIdx.x, lwe_params),
        lut,
        bsk,
        log_chi,
        log_v,
        lwe_params,
        glwe_params,
        radix,
        scratch
    );
}

#ifdef THREAD_BLOCK_CLUSTERS
#include "../ops/parallel_bootstrapping.cuh"
#endif 