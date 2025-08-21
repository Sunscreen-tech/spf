#pragma once
#include "../../src/entities/dst_array.cuh"
#include "../../src/entities/polynomial.cuh"
#include "../../src/entities/scratch.cuh"
#include "../../src/ops/polynomial.cuh"
#include "../../src/params.cuh"

extern "C" __global__ void can_polynomial_rountrip_fft(
    const DstArray<Polynomial<uint64_t>> *__restrict__ x,
    DstArray<Polynomial<uint64_t>> *__restrict__ y,
    uint8_t *scratch_buf,
    const u32 n)
{
    auto degree = PolynomialDegree(n);
    auto allocator = PerBlockStackAllocator(scratch_buf, get_scratch_size());
    auto tmp = allocator.alloc<PolynomialFft<Complex<double>>>(degree);
    auto x_i = x->nth(blockIdx.x, degree);
    auto y_i = y->nth(blockIdx.x, degree);

    x_i->fft(*tmp, degree);
    tmp->ifft(y_i, degree);
}

extern "C" __global__ void can_polynomial_rountrip_fft_inplace(
    const DstArray<Polynomial<uint64_t>> *__restrict__ x,
    DstArray<Polynomial<uint64_t>> *__restrict__ y,
    uint8_t *scratch_buf, // Unused, but want to match interface of can_polynomial_rountrip_fft
    const u32 n)
{
    auto degree = PolynomialDegree(n);
    auto x_i = x->nth(blockIdx.x, degree);
    auto y_i = y->nth(blockIdx.x, degree);

    auto s_in = get_fft_scratch<Polynomial<uint64_t>>();

    BLOCK_COPY(s_in->coeffs(), x_i->coeffs(), n);

    auto s_fft = s_in->fft_inplace<Complex<double>>(degree);
    auto s_out = s_fft->ifft_inplace<uint64_t>(degree);

    BLOCK_COPY(y_i->coeffs(), s_out->coeffs(), n);
}

extern "C" __global__ void can_sub_polynomials(
    DstArray<Polynomial<uint64_t>> *c,
    const DstArray<Polynomial<uint64_t>> *a,
    const DstArray<Polynomial<uint64_t>> *b,
    u32 d)
{
    auto degree = PolynomialDegree(d);

    auto c_i = c->nth(blockIdx.x, degree);
    auto a_i = a->nth(blockIdx.x, degree);
    auto b_i = b->nth(blockIdx.x, degree);

    polynomial_sub(c_i, a_i, b_i, degree);
}

extern "C" __global__ void can_add_polynomials(
    DstArray<Polynomial<uint64_t>> *c,
    const DstArray<Polynomial<uint64_t>> *a,
    const DstArray<Polynomial<uint64_t>> *b,
    u32 d)
{
    auto degree = PolynomialDegree(d);

    auto c_i = c->nth(blockIdx.x, degree);
    auto a_i = a->nth(blockIdx.x, degree);
    auto b_i = b->nth(blockIdx.x, degree);

    polynomial_add(c_i, a_i, b_i, degree);
}

extern "C" __global__ void can_mad_polynomials_pre_fftd(
    DstArray<PolynomialFft<Complex<double>>> *__restrict__ c_fft,
    const DstArray<PolynomialFft<Complex<double>>> *__restrict__ a_fft,
    const DstArray<PolynomialFft<Complex<double>>> *__restrict__ b_fft,
    u32 d)
{
    auto degree = PolynomialDegree(d);

    auto c_i_fft = c_fft->nth(blockIdx.x, degree);
    auto a_i_fft = a_fft->nth(blockIdx.x, degree);
    auto b_i_fft = b_fft->nth(blockIdx.x, degree);

    polynomial_mad(c_i_fft, a_i_fft, b_i_fft, degree);
}

extern "C" __global__ void can_multiply_non_negacyclic_polynomials(
    DstArray<Polynomial<Complex<double>>> *__restrict__ c,
    const DstArray<Polynomial<Complex<double>>> *__restrict__ a,
    const DstArray<Polynomial<Complex<double>>> *__restrict__ b,
    const u32 d)
{
    auto degree = PolynomialDegree(d);

    __shared__ Complex<double> a_s[1024];
    __shared__ Complex<double> b_s[1024];
    __shared__ Complex<double> c_s[1024];

    auto a_i = a->nth(blockIdx.x, degree);
    auto b_i = b->nth(blockIdx.x, degree);
    auto c_i = c->nth(blockIdx.x, degree);

    BLOCK_COPY(a_s, a_i->coeffs(), d);
    BLOCK_COPY(b_s, b_i->coeffs(), d);

    fft_noreorder(a_s, d);
    fft_noreorder(b_s, d);

    BLOCK_FOR_EACH(i, d)
    {
        c_s[i] = a_s[i] * b_s[i];
    }

    __syncthreads();

    ifft_noreorder(c_s, d);

    BLOCK_COPY(c_i->coeffs(), c_s, d);
}

extern "C" __global__ void can_mad_polynomials(
    DstArray<Polynomial<double>> *__restrict__ result,
    DstArray<Polynomial<uint64_t>> *__restrict__ c,
    const DstArray<Polynomial<uint64_t>> *__restrict__ a,
    const DstArray<Polynomial<uint64_t>> *__restrict__ b,
    uint8_t *scratch_buf,
    u32 d)
{
    auto degree = PolynomialDegree(d);
    auto scratch = PerBlockStackAllocator(scratch_buf, get_scratch_size());

    auto c_i = c->nth(blockIdx.x, degree);
    auto a_i = a->nth(blockIdx.x, degree);
    auto b_i = b->nth(blockIdx.x, degree);

    auto c_i_fft = scratch.alloc<PolynomialFft<Complex<double>>>(d);
    auto a_i_fft = scratch.alloc<PolynomialFft<Complex<double>>>(d);
    auto b_i_fft = scratch.alloc<PolynomialFft<Complex<double>>>(d);

    c_i->fft(*c_i_fft, degree);
    a_i->fft(*a_i_fft, degree);
    b_i->fft(*b_i_fft, degree);

    polynomial_mad(*c_i_fft, *a_i_fft, *b_i_fft, degree);

    // Set the modulo-reduced result
    c_i_fft->ifft(c_i, degree);
    PolynomialDegree n_div_2 = PolynomialDegree{degree.val / 2};

    auto s_in = get_fft_scratch<Complex<double>>();
    BLOCK_COPY(s_in, c_i_fft->coeffs(), n_div_2.val);

    // Compute the non modulo-reduced result so we can check it as well in our test.
    auto s_out = twisted_ifft_noreorder(s_in, degree.val);

    auto result_i = result->nth(blockIdx.x, degree);
    BLOCK_COPY(result_i->coeffs(), s_out, degree.val);
}