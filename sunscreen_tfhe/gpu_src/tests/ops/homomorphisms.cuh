#pragma once

#include <cstdint>

#include "../../src/params.cuh"
#include "../../src/entities/dst_array.cuh"
#include "../../src/entities/glwe.cuh"
#include "../../src/ops/homomorphisms.cuh"

extern "C" __global__ void can_glwe_sub(
    cuda::std::complex<f64> *c_buf,
    const cuda::std::complex<f64> *a_buf,
    const cuda::std::complex<f64> *b_buf)
{
    const auto params = GLWE_1_2048_128;

    auto c = DstArray<GlweCiphertext>::from_ptr(c_buf);
    auto a = DstArray<GlweCiphertext>::from_ptr(a_buf);
    auto b = DstArray<GlweCiphertext>::from_ptr(b_buf);

    auto c_i = c.nth(blockIdx.x, params);
    auto a_i = a.nth(blockIdx.x, params);
    auto b_i = b.nth(blockIdx.x, params);

    glwe_sub(c_i, a_i, b_i, params);
}

extern "C" __global__ void can_glwe_add(
    cuda::std::complex<f64> *__restrict__ c_buf,
    const cuda::std::complex<f64> *__restrict__ a_buf,
    const cuda::std::complex<f64> *__restrict__ b_buf)
{
    const auto params = GLWE_1_2048_128;

    auto c = DstArray<GlweCiphertext>::from_ptr(c_buf);
    auto a = DstArray<GlweCiphertext>::from_ptr(a_buf);
    auto b = DstArray<GlweCiphertext>::from_ptr(b_buf);

    auto c_i = c.nth(blockIdx.x, params);
    auto a_i = a.nth(blockIdx.x, params);
    auto b_i = b.nth(blockIdx.x, params);

    glwe_add(c_i, a_i, b_i, params);
}

extern "C" __global__ void can_glwe_polynomial_mad(
    cuda::std::complex<f64> *__restrict__ c_buf,
    const cuda::std::complex<f64> *__restrict__ a_buf,
    const cuda::std::complex<f64> *__restrict__ b_buf,
    cuda::std::complex<f64> *__restrict__ scratch_buffer)
{
    const auto &glwe = GLWE_1_2048_128;

    auto c = DstArray<GlweCiphertext>::from_ptr(c_buf);
    auto a = DstArray<GlweCiphertext>::from_ptr(a_buf);
    auto b = DstArray<Polynomial>::from_ptr(b_buf);

    auto c_i = c.nth(blockIdx.x, glwe);
    auto a_i = a.nth(blockIdx.x, glwe);
    auto b_i = b.nth(blockIdx.x, glwe.polynomial_degree());

    auto scratch = PerBlockStackAllocator(scratch_buffer, get_scratch_size());

    auto c_i_fft = scratch.alloc<GlweCiphertextFft>(glwe);
    auto a_i_fft = scratch.alloc<GlweCiphertextFft>(glwe);
    auto b_i_fft = scratch.alloc<PolynomialFft>(glwe.polynomial_degree());

    c_i.fft(*c_i_fft, glwe);
    a_i.fft(*a_i_fft, glwe);
    b_i.fft(*b_i_fft, glwe.polynomial_degree());

    glwe_polynomial_mad(*c_i_fft, *a_i_fft, *b_i_fft, glwe);

    // Store the IFFT back to c_i.
    c_i_fft->ifft(c_i, glwe);
}

extern "C" __global__ void can_polynomial_glev_mad(
    cuda::std::complex<f64>> *__restrict__ c_buf,
    const cuda::std::complex<f64> *__restrict__ a_buf,
    const cuda::std::complex<f64> *__restrict__ b_buf,
    cuda::std::complex<f64> *__restrict__ scratch_buffer)
{
    const auto &radix = PBS_RADIX_2_16_128;
    const auto &glwe = GLWE_1_2048_128;
    auto scratch = PerBlockStackAllocator(scratch_buffer, get_scratch_size());

    auto c = DstArray<GlweCiphertext>::from_ptr(c_buf);
    auto a = DstArray<Polynomial>::from_ptr(a_buf);
    auto b = DstArray<GlevCiphertext>::from_ptr(b_buf);

    auto c_i = c.nth(blockIdx.x, glwe);
    auto a_i = a.nth(blockIdx.x, glwe.polynomial_degree());
    auto b_i = b.nth(blockIdx.x, std::tuple(glwe, radix));

    auto c_i_fft = scratch.alloc<GlweCiphertextFft>(glwe);
    auto a_i_fft = scratch.alloc<PolynomialFft>(glwe);
    auto b_i_fft = scratch.alloc<GlevCiphertextFft>(std::tuple(glwe, radix));

    c_i.fft(c_i_fft);
    a_i.fft(a_i_fft);
    b_i.fft(b_i_fft);

    decomposed_polynomial_glev_mad(c_i_fft, a_i_fft, b_i_fft, glwe, radix, scratch);

    c_i_fft.ifft(c_i, glwe);
}

extern "C" __global__ void can_glwe_ggsw_mad(
    cuda::std::complex<f64> *__restrict__ c_buf,
    const cuda::std::complex<f64> *__restrict__ a_buf,
    const cuda::std::complex<f64> *__restrict__ b_buf,
    cuda::std::complex<f64> *__restrict__ scratch_buffer)
{
    const auto &radix = PBS_RADIX_2_16_128;
    const auto &glwe = GLWE_1_2048_128;
    auto scratch = PerBlockStackAllocator(scratch_buffer, get_scratch_size());

    auto c = DstArray<GlweCiphertext>::from_ptr(c_buf);
    auto a = DstArray<GlweCiphertext>::from_ptr(a_buf);
    auto b = DstArray<GgswCiphertext>::from_ptr(b_buf);

    auto c_i = c.nth(blockIdx.x, glwe);
    auto a_i = a.nth(blockIdx.x, glwe);
    auto b_i = b.nth(blockIdx.x, std::tuple(glwe, radix));

    auto c_i_fft = scratch.alloc<GlweCiphertextFft>(glwe);
    auto b_i_fft = scratch.alloc<GgswCiphertextFft>(std::tuple(glwe, radix));

    c_i.fft(c_i_fft, glwe);
    b_i.fft(b_i_fft, std::tuple(glwe, radix));

    glwe_ggsw_mad(c_i_fft, a_i, b_i_fft, glwe, radix, scratch);

    c_i_fft.ifft(c_i, glwe);
}

extern "C" __global__ void can_cmux(
    cuda::std::complex<f64> *__restrict__ c_buf,
    const cuda::std::complex<f64> *__restrict__ a_buf,
    const cuda::std::complex<f64> *__restrict__ b_buf,
    const cuda::std::complex<f64> *__restrict__ sel_buf,
    cuda::std::complex<f64> *__restrict__ scratch_buffer)
{
    const auto &radix = PBS_RADIX_2_16_128;
    const auto &glwe = GLWE_1_2048_128;
    auto scratch = PerBlockStackAllocator(scratch_buffer, get_scratch_size());

    auto c = DstArray<GlweCiphertext>::from_ptr(c_buf);
    auto a = DstArray<GlweCiphertext>::from_ptr(a_buf);
    auto b = DstArray<GlweCiphertext>::from_ptr(b_buf);
    auto sel = DstArray<GgswCiphertext>::from_ptr(sel_buf);

    auto c_i = c.nth(blockIdx.x, glwe);
    auto a_i = a.nth(blockIdx.x, glwe);
    auto b_i = b.nth(blockIdx.x, glwe);
    auto sel_i = sel.nth(blockIdx.x, std::tuple(glwe, radix));
    
    auto sel_i_fft = scratch.alloc<GgswCiphertextFft>();
    sel_i.fft(sel_i_fft, std::tuple(glwe, radix));

    cmux(c_i, a_i, b_i, sel_i_fft, glwe, radix, scratch);
}