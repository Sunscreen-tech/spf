#pragma once
#include <cuda/std/complex>
#include <tuple>

#include "../math/primitives.cuh"
#include "../entities/bootstrap_key.cuh"
#include "../params.cuh"

__global__ void kernel_fft_bootstrap_key(
    cuda::std::complex<f64> *__restrict__ bsk_fft_buf,
    const cuda::std::complex<f64> *__restrict__ bsk_buf
) {
    // TODO: Allow configurable params
    auto lwe = LWE_637_128;
    auto glwe = GLWE_1_2048_128;
    auto pbs_radix = PBS_RADIX_2_16_128;

    auto bsk = BootstrapKey::from_ptr(bsk_buf);
    auto bsk_fft = BootstrapKeyFft::from_ptr(bsk_buf);

    auto size_info = std::tuple(lwe, glwe, pbs_radix);
    auto bsk_i = bsk.s(blockIdx.x, size_info);
    auto bsk_fft_i = bsk_fft.s(blockIdx.x, size_info);

    bsk_i.fft(bsk_fft_i, std::tuple(glwe, pbs_radix));
}