#pragma once
#include <cuda/std/complex>

#include "../../src/entities/dst_array.cuh"
#include "../../src/entities/polynomial.cuh"
#include "../../src/entities/scratch.cuh"
#include "../../src/ops/polynomial.cuh"
#include "../../src/params.cuh"

extern "C" __global__ void can_polynomial_rountrip_fft(
    const cuda::std::complex<f64> *__restrict__ x_buf,
    cuda::std::complex<f64> *__restrict__ y_buf,
    cuda::std::complex<f64> *__restrict__ scratch_buf, // unused
    const u32 n)
{
    auto x = DstArray<Polynomial>::from_ptr(x_buf);
    auto y = DstArray<Polynomial>::from_ptr(y_buf);
    
    auto degree = PolynomialDegree(n);
    auto tmp = PolynomialFft(get_fft_scratch());
    auto x_i = x.nth(blockIdx.x, degree);
    auto y_i = y.nth(blockIdx.x, degree);

    x_i.fft(tmp, degree);
    tmp.ifft(y_i, degree);
}

extern "C" __global__ void can_polynomial_rountrip_fft_inplace(
    const cuda::std::complex<f64> *__restrict__ x_buf,
    cuda::std::complex<f64> *__restrict__ y_buf,
    cuda::std::complex<f64> *__restrict__ scratch_buf, // unused
    const u32 n)
{
    auto x = DstArray<Polynomial>::from_ptr(x_buf);
    auto y = DstArray<Polynomial>::from_ptr(y_buf);

    auto degree = PolynomialDegree(n);
    auto x_i = x.nth(blockIdx.x, degree);
    auto y_i = y.nth(blockIdx.x, degree);

    auto s_in = Polynomial(get_fft_scratch());

    x_i.clone_into(s_in, degree);

    auto s_fft = std::move(s_in).fft_inplace(degree);
    auto s_out = std::move(s_fft).ifft_inplace(degree);

    s_out.clone_into(y_i, degree);
}

extern "C" __global__ void can_sub_polynomials(
    cuda::std::complex<f64> *c_buf,
    const cuda::std::complex<f64> *a_buf,
    const cuda::std::complex<f64> *b_buf,
    u32 d)
{
    auto degree = PolynomialDegree(d);
    auto c = DstArray<Polynomial>::from_ptr(c_buf);
    auto a = DstArray<Polynomial>::from_ptr(a_buf);
    auto b = DstArray<Polynomial>::from_ptr(b_buf);

    auto c_i = c.nth(blockIdx.x, degree);
    auto a_i = a.nth(blockIdx.x, degree);
    auto b_i = b.nth(blockIdx.x, degree);

    polynomial_sub(c_i, a_i, b_i, degree);
}

extern "C" __global__ void can_add_polynomials(
    cuda::std::complex<f64> *c_buf,
    const cuda::std::complex<f64> *a_buf,
    const cuda::std::complex<f64> *b_buf,
    u32 d)
{
    auto degree = PolynomialDegree(d);
    auto c = DstArray<Polynomial>::from_ptr(c_buf);
    auto a = DstArray<Polynomial>::from_ptr(a_buf);
    auto b = DstArray<Polynomial>::from_ptr(b_buf);

    auto c_i = c.nth(blockIdx.x, degree);
    auto a_i = a.nth(blockIdx.x, degree);
    auto b_i = b.nth(blockIdx.x, degree);

    polynomial_add(c_i, a_i, b_i, degree);
}

extern "C" __global__ void can_mad_polynomials_pre_fftd(
    cuda::std::complex<f64> *__restrict__ c_fft_buf,
    const cuda::std::complex<f64> *__restrict__ a_fft_buf,
    const cuda::std::complex<f64> *__restrict__ b_fft_buf,
    u32 d)
{
    auto degree = PolynomialDegree(d);
    auto c_fft = DstArray<PolynomialFft>::from_ptr(c_fft_buf);
    auto a_fft = DstArray<PolynomialFft>::from_ptr(a_fft_buf);
    auto b_fft = DstArray<PolynomialFft>::from_ptr(b_fft_buf);

    auto c_i_fft = c_fft.nth(blockIdx.x, degree);
    auto a_i_fft = a_fft.nth(blockIdx.x, degree);
    auto b_i_fft = b_fft.nth(blockIdx.x, degree);

    polynomial_mad(c_i_fft, a_i_fft, b_i_fft, degree);
}

extern "C" __global__ void can_multiply_non_negacyclic_polynomials(
    cuda::std::complex<f64> *__restrict__ c_buf,
    const cuda::std::complex<f64> *__restrict__ a_buf,
    const cuda::std::complex<f64> *__restrict__ b_buf,
    const u32 d)
{
    auto degree = PolynomialDegree(d);

    auto a = DstArray<Polynomial>::from_ptr(a_buf);
    auto b = DstArray<Polynomial>::from_ptr(b_buf);
    auto c = DstArray<Polynomial>::from_ptr(c_buf);

    auto a_i = a.nth(blockIdx.x, degree);
    auto b_i = b.nth(blockIdx.x, degree);
    auto c_i = c.nth(blockIdx.x, degree);

    auto p_shared = DstArray<Polynomial>(get_fft_scratch());
    auto a_s = p_shared.nth(0, degree);
    auto b_s = p_shared.nth(1, degree);
    auto c_s = p_shared.nth(2, degree);

    a_i.clone_into(a_s, d);
    b_i.clone_into(b_s, d);

    fft_noreorder(a_s.coeffs().as_complex(), d);
    fft_noreorder(b_s.coeffs().as_complex(), d);

    BLOCK_FOR_EACH(i, d)
    {
        c_s.coeffs().as_complex()[i] = a_s.coeffs().as_complex()[i] * b_s.coeffs().as_complex()[i];
    }

    __syncthreads();

    ifft_noreorder(c_s.coeffs().as_complex(), d);

    c_s.clone_into(c_i, d);
}

extern "C" __global__ void can_mad_polynomials(
    cuda::std::complex<f64> *__restrict__ result_buf,
    cuda::std::complex<f64> *__restrict__ c_buf,
    const cuda::std::complex<f64> *__restrict__ a_buf,
    const cuda::std::complex<f64> *__restrict__ b_buf,
    cuda::std::complex<f64> *__restrict__ scratch_buf,
    u32 d)
{
    auto degree = PolynomialDegree(d);
    auto scratch = PerBlockStackAllocator(scratch_buf, get_scratch_size());

    auto c = DstArray<Polynomial>::from_ptr(c_buf);
    auto a = DstArray<Polynomial>::from_ptr(a_buf);
    auto b = DstArray<Polynomial>::from_ptr(b_buf);
    auto c_i = c.nth(blockIdx.x, degree);
    auto a_i = a.nth(blockIdx.x, degree);
    auto b_i = b.nth(blockIdx.x, degree);

    auto c_i_fft = scratch.alloc<PolynomialFft>(degree);
    auto a_i_fft = scratch.alloc<PolynomialFft>(degree);
    auto b_i_fft = scratch.alloc<PolynomialFft>(degree);

    c_i.fft(*c_i_fft, degree);
    a_i.fft(*a_i_fft, degree);
    b_i.fft(*b_i_fft, degree);

    polynomial_mad(*c_i_fft, *a_i_fft, *b_i_fft, degree);

    // Set the modulo-reduced result
    (*c_i_fft).ifft(c_i, degree);
    PolynomialDegree n_div_2 = PolynomialDegree{degree.val / 2};

    // Compute the non modulo-reduced result so we can check it as well in our test.
    twisted_ifft_noreorder((*c_i_fft).coeffs(), degree.val);

    auto result = DstArray<Polynomial>::from_ptr(result_buf);
    auto result_i = result.nth(blockIdx.x, degree);
    BLOCK_COPY(result_i.coeffs().as_f64(), (*c_i_fft).coeffs().as_f64(), degree.val);
}

extern "C" __global__ void can_mad_polynomials_inplace(
    cuda::std::complex<f64> *__restrict__ result_buf, // unused
    cuda::std::complex<f64> *__restrict__ c_buf,
    const cuda::std::complex<f64> *__restrict__ a_buf,
    const cuda::std::complex<f64> *__restrict__ b_buf,
    cuda::std::complex<f64> *__restrict__ scratch_buf, // unused
    u32 d)
{
    auto degree = PolynomialDegree(d);
    auto scratch = PerBlockStackAllocator(scratch_buf, get_scratch_size());

    auto c = DstArray<Polynomial>::from_ptr(c_buf);
    auto a = DstArray<Polynomial>::from_ptr(a_buf);
    auto b = DstArray<Polynomial>::from_ptr(b_buf);
    auto c_i = c.nth(blockIdx.x, degree);
    auto a_i = a.nth(blockIdx.x, degree);
    auto b_i = b.nth(blockIdx.x, degree);

    __shared__ cuda::std::complex<f64> s_0[1024];
    __shared__ cuda::std::complex<f64> s_1[1024];
    __shared__ cuda::std::complex<f64> s_2[1024];

    auto a_s = Polynomial::from_ptr(s_0);
    auto b_s = Polynomial::from_ptr(s_1);
    auto c_s = Polynomial::from_ptr(s_2);

    a_i.clone_into(a_s, degree);
    b_i.clone_into(b_s, degree);
    c_i.clone_into(c_s, degree);

    auto a_s_fft = std::move(a_s).fft_inplace(degree);
    auto b_s_fft = std::move(b_s).fft_inplace(degree);
    auto c_s_fft = std::move(c_s).fft_inplace(degree);
    
    polynomial_mad(c_s_fft, a_s_fft, b_s_fft, degree);

    // Set the modulo-reduced result
    c_s = std::move(c_s_fft).ifft_inplace(degree);
    
    c_s.clone_into(c_i, degree);
}

extern "C" __global__ void inplace_vs_out_of_place_fft(
    cuda::std::complex<f64> *__restrict__ out_of_place_buf,
    cuda::std::complex<f64> *__restrict__ inplace_buf,
    const cuda::std::complex<f64> *__restrict__ input_buf,
    u32 d)
{
    auto degree = PolynomialDegree(d);

    auto p_s = Polynomial(get_fft_scratch());
    
    auto input = DstArray<Polynomial>::from_ptr(input_buf);
    auto out_of_place = DstArray<PolynomialFft>::from_ptr(input_buf);
    auto inplace = DstArray<PolynomialFft>::from_ptr(input_buf);

    auto input_i = input.nth(blockIdx.x, degree);
    auto out_of_place_i = out_of_place.nth(blockIdx.x, degree);
    auto inplace_i = inplace.nth(blockIdx.x, degree);

    input_i.clone_into(p_s, degree);
    auto a_s_fft = std::move(p_s).fft_inplace(degree);

    a_s_fft.clone_into(inplace_i, degree);
    input_i.fft(out_of_place_i, degree);
}

extern "C" __global__ void inplace_vs_out_of_place_ifft(
    cuda::std::complex<f64> *__restrict__ out_of_place_buf,
    cuda::std::complex<f64> *__restrict__ inplace_buf,
    const cuda::std::complex<f64> *__restrict__ input_buf,
    u32 d)
{
    auto degree = PolynomialDegree(d);

    auto p_s = PolynomialFft(get_fft_scratch());
    
    auto input = DstArray<PolynomialFft>::from_ptr(input_buf);
    auto out_of_place = DstArray<Polynomial>::from_ptr(input_buf);
    auto inplace = DstArray<Polynomial>::from_ptr(input_buf);

    auto input_i = input.nth(blockIdx.x, degree);
    auto out_of_place_i = out_of_place.nth(blockIdx.x, degree);
    auto inplace_i = inplace.nth(blockIdx.x, degree);

    input_i.clone_into(p_s, degree);
    auto a_s_fft = std::move(p_s).ifft_inplace(degree);

    a_s_fft.clone_into(inplace_i, degree);
    input_i.ifft(out_of_place_i, degree);
}