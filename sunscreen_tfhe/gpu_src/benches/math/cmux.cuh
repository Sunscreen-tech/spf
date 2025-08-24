#pragma once
#include <cstdint>
#include <cuda/std/complex>

#include "../../src/entities/dst_array.cuh"
#include "../../src/entities/glwe.cuh"
#include "../../src/entities/ggsw.cuh"
#include "../../src/entities/scratch.cuh"
#include "../../src/ops/homomorphisms.cuh"
#include "../../src/params.cuh"

extern "C" __global__ void synthetic_pbs(
    cuda::std::complex<f64> *__restrict__ result_buf,
    const cuda::std::complex<f64> *__restrict__ bsk_buf,
    cuda::std::complex<f64> *__restrict__ scratch_buf
) {
    auto lwe = LWE_637_128;
    auto glwe = GLWE_1_2048_128;
    auto pbs_radix = PBS_RADIX_2_16_128;
    auto scratch = PerBlockStackAllocator(scratch_buf, get_scratch_size());

    auto tmp = scratch.alloc<GlweCiphertext>(glwe);
    auto rotated = scratch.alloc<GlweCiphertext>(glwe);
    auto result = DstArray<GlweCiphertext>::from_ptr(result_buf);
    auto bsk = DstArray<GgswCiphertextFft>::from_ptr(bsk_buf);

    auto result_i = result.nth(blockIdx.x, glwe);

    for (u32 i = 0; i < lwe.size.val; i++) {
        result_i.clone_into(*tmp, glwe);
        result_i.clone_into(*rotated, glwe);

        auto enc_s_fft = bsk.nth(i, std::tuple(glwe, pbs_radix));

        cmux(result_i, *tmp, *rotated, enc_s_fft, glwe, pbs_radix, scratch);
    }
}