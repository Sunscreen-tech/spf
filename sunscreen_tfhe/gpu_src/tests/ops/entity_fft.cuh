#pragma once

#include "../../src/entities/bootstrap_key.cuh"
#include "../../src/entities/dst_array.cuh"
#include "../../src/entities/glwe.cuh"
#include "../../src/entities/scratch.cuh"
#include "../../src/ops/homomorphisms.cuh"
#include "../../src/params.cuh"


extern "C" __global__ void compare_glwe_fft(
    cuda::std::complex<f64> *__restrict__ c_buf,
    cuda::std::complex<f64> *__restrict__ c_fft_buf,
    const cuda::std::complex<f64> *__restrict__ x_buf
) {
    auto scratch = get_shared_allocator(32 * 1024);
    const auto &glwe = GLWE_1_2048_128;

    auto c = DstArray<GlweCiphertext>::from_ptr(c_buf);
    auto c_fft = DstArray<GlweCiphertextFft>::from_ptr(c_fft_buf);
    auto x = DstArray<GlweCiphertext>::from_ptr(x_buf);

    auto x_i = x.nth(blockIdx.x, glwe);
    auto c_i = c.nth(blockIdx.x, glwe);
    auto c_fft_i = c_fft.nth(blockIdx.x, glwe);

    x_i.fft(c_fft_i, glwe, scratch);
    c_fft_i.ifft(c_i, glwe, scratch);
}

extern "C" __global__ void can_recover_lwe_sk_from_bsk(
    cuda::std::complex<f64> *__restrict__ glwe_out_buf,
    const cuda::std::complex<f64> *__restrict__ glwe_in_buf,
    const cuda::std::complex<f64> *__restrict__ bsk_buf,
    const LweDef lwe,
    const GlweDef glwe,
    const RadixDecomposition radix,
    cuda::std::complex<f64> * __restrict__ scratch_buf
) {
    auto scratch = get_shared_allocator(96 * 1024);
    auto scratch_g = PerBlockStackAllocator(scratch_buf, get_scratch_size());

    auto glwe_fft_s = scratch.alloc<GlweCiphertextFft>(glwe);
    // auto glwe_fft_s = scratch_g.alloc<GlweCiphertextFft>(glwe);
    (*glwe_fft_s).clear(glwe);

    auto glwe_out = DstArray<GlweCiphertext>::from_ptr(glwe_out_buf);
    auto glwe_in = DstArray<GlweCiphertext>::from_ptr(glwe_in_buf);
    auto bsk = BootstrapKeyFft::from_ptr(bsk_buf);

    auto glwe_in_i = glwe_in.nth(blockIdx.x, glwe);
    auto glwe_out_i = glwe_out.nth(blockIdx.x, glwe);
    auto ggsw_fft_i = bsk.s(blockIdx.x, cuda::std::tuple(lwe, glwe, radix));
 
    glwe_ggsw_mad(*glwe_fft_s, glwe_in_i, ggsw_fft_i, glwe, radix, scratch);

    (*glwe_fft_s).ifft(glwe_out_i, glwe, scratch);
}

extern "C" __global__ void can_roundtrip_fft_glwe(
    cuda::std::complex<f64> *__restrict__ glwe_out_buf,
    cuda::std::complex<f64> *__restrict__ glwe_fft_out_buf,
    const cuda::std::complex<f64> *__restrict__ glwe_in_buf,
    const GlweDef glwe
) {
    auto scratch = get_shared_allocator(96 * 1024);

    auto glwe_out = DstArray<GlweCiphertext>::from_ptr(glwe_out_buf);
    auto glwe_out_fft = DstArray<GlweCiphertextFft>::from_ptr(glwe_fft_out_buf);
    auto glwe_in = DstArray<GlweCiphertext>::from_ptr(glwe_in_buf);

    auto glwe_out_i = glwe_out.nth(blockIdx.x, glwe);
    auto glwe_out_fft_i = glwe_out_fft.nth(blockIdx.x, glwe);
    auto glwe_in_i = glwe_in.nth(blockIdx.x, glwe);

    glwe_in_i.fft(glwe_out_fft_i, glwe, scratch);
    glwe_out_fft_i.ifft(glwe_out_i, glwe, scratch);
}

extern "C" __global__ void can_roundtrip_fft_glev(
    cuda::std::complex<f64> *__restrict__ glev_out_buf,
    cuda::std::complex<f64> *__restrict__ glev_fft_out_buf,
    const cuda::std::complex<f64> *__restrict__ glev_in_buf,
    const GlweDef glwe,
    const RadixDecomposition radix
) {
    auto scratch = get_shared_allocator(96 * 1024);

    auto glev_out = DstArray<GlevCiphertext>::from_ptr(glev_out_buf);
    auto glev_out_fft = DstArray<GlevCiphertextFft>::from_ptr(glev_fft_out_buf);
    auto glev_in = DstArray<GlevCiphertext>::from_ptr(glev_in_buf);

    auto glev_out_i = glev_out.nth(blockIdx.x, cuda::std::tuple(glwe, radix));
    auto glev_out_fft_i = glev_out_fft.nth(blockIdx.x, cuda::std::tuple(glwe, radix));
    auto glev_in_i = glev_in.nth(blockIdx.x, cuda::std::tuple(glwe, radix));

    glev_in_i.fft(glev_out_fft_i, cuda::std::tuple(glwe, radix), scratch);
    glev_out_fft_i.ifft(glev_out_i, cuda::std::tuple(glwe, radix), scratch);
}

extern "C" __global__ void can_roundtrip_fft_ggsw(
    cuda::std::complex<f64> *__restrict__ ggsw_out_buf,
    cuda::std::complex<f64> *__restrict__ ggsw_fft_out_buf,
    const cuda::std::complex<f64> *__restrict__ ggsw_in_buf,
    const GlweDef glwe,
    const RadixDecomposition radix
) {
    auto scratch = get_shared_allocator(32 * 1024);


    auto ggsw_out = DstArray<GgswCiphertext>::from_ptr(ggsw_out_buf);
    auto ggsw_out_fft = DstArray<GgswCiphertextFft>::from_ptr(ggsw_fft_out_buf);
    auto ggsw_in = DstArray<GgswCiphertext>::from_ptr(ggsw_in_buf);

    auto ggsw_out_i = ggsw_out.nth(blockIdx.x, cuda::std::tuple(glwe, radix));
    auto ggsw_out_fft_i = ggsw_out_fft.nth(blockIdx.x, cuda::std::tuple(glwe, radix));
    auto ggsw_in_i = ggsw_in.nth(blockIdx.x, cuda::std::tuple(glwe, radix));

    ggsw_in_i.fft(ggsw_out_fft_i, cuda::std::tuple(glwe, radix), scratch);
    ggsw_out_fft_i.ifft(ggsw_out_i, cuda::std::tuple(glwe, radix), scratch);
}