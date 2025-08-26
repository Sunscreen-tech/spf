#pragma once
#include "../ops/bootstrapping.cuh"

extern "C" __global__ void kernel_generalized_programmable_bootstrap(
    cuda::std::complex<f64> **__restrict__ output_buf,
    const cuda::std::complex<f64> **__restrict__ input_buf,
    const cuda::std::complex<f64> **__restrict__ lut,
    const cuda::std::complex<f64> **__restrict__ bsk,
    u32 log_chi,
    u32 log_v,
    const LweDef *__restrict__ lwe_params,
    const GlweDef *__restrict__ glwe_params,
    const RadixDecomposition *__restrict__ radix,
    u32 local_storage_amount
) {
    auto scratch = PerBlockStackAllocator(get_fft_scratch().as_complex(), local_storage_amount, true);


}