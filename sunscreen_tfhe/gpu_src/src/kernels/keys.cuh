#pragma once
#include <cuda/std/complex>
#include <tuple>

#include "../math/primitives.cuh"
#include "../entities/bootstrap_key.cuh"
#include "../params.cuh"

extern "C" __global__ void kernel_fft_bootstrap_key(
    cuda::std::complex<f64> *__restrict__ bsk_fft_buf,
    const cuda::std::complex<f64> *__restrict__ bsk_buf,
    LweDef lwe,
    GlweDef glwe,
    RadixDecomposition pbs_radix)
{
    auto bsk = BootstrapKey::from_ptr(bsk_buf);
    auto bsk_fft = BootstrapKeyFft::from_ptr(bsk_buf);

    auto size_info = std::tuple(lwe, glwe, pbs_radix);
    auto bsk_i = bsk.s(blockIdx.x, size_info);
    auto bsk_fft_i = bsk_fft.s(blockIdx.x, size_info);

    bsk_i.fft(bsk_fft_i, std::tuple(glwe, pbs_radix));
}