#pragma once
#include <cstdint>

#include "../../src/entities/dst_array.cuh"
#include "../../src/entities/glwe.cuh"
#include "../../src/entities/ggsw.cuh"
#include "../../src/entities/scratch.cuh"
#include "../../src/ops/homomorphisms.cuh"
#include "../../src/params.cuh"

extern "C" __global__ void synthetic_pbs(
    DstArray<GlweCiphertext<uint64_t>> *__restrict__ result,
    const DstArray<GgswCiphertextFft<Complex<double>>> *__restrict__ bsk,
    uint8_t *__restrict__ scratch_buf
) {
    auto lwe = LWE_637_128;
    auto glwe = GLWE_1_2048_128;
    auto pbs_radix = PBS_RADIX_2_16_128;
    auto scratch = PerBlockStackAllocator(scratch_buf, get_scratch_size());

    auto tmp = scratch.alloc<GlweCiphertext<uint64_t>>(glwe);
    auto rotated = scratch.alloc<GlweCiphertext<uint64_t>>(glwe);
    auto result_i = result->nth(blockIdx.x, glwe);

    for (uint32_t i = 0; i < lwe.size.val; i++) {
        result_i->clone_into(*tmp, glwe);
        result_i->clone_into(*rotated, glwe);

        auto enc_s_fft = bsk->nth(i, std::tuple(glwe, pbs_radix));

        cmux(result_i, *tmp, *rotated, enc_s_fft, glwe, pbs_radix, scratch);
    }
}