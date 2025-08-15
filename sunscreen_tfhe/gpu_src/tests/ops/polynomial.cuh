#pragma once
#include "../../src/entities/dst_array.cuh"
#include "../../src/entities/polynomial.cuh"
#include "../../src/entities/scratch.cuh"
#include "../../src/ops/polynomial.cuh"

extern "C" __global__ void can_polynomial_rountrip_fft(
    const DstArray<Polynomial<uint64_t>> *__restrict__ x,
    DstArray<Polynomial<uint64_t>> *__restrict__ y,
    uint8_t *scratch_buf,
    const uint32_t n
) {
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
    const uint32_t n
) {
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
    uint32_t d
) {
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
    uint32_t d
) {
    auto degree = PolynomialDegree(d);

    auto c_i = c->nth(blockIdx.x, degree);
    auto a_i = a->nth(blockIdx.x, degree);
    auto b_i = b->nth(blockIdx.x, degree);

    polynomial_add(c_i, a_i, b_i, degree);
}

extern "C" __global__ void can_mad_polynomials(
    DstArray<Polynomial<uint64_t>> *c,
    const DstArray<Polynomial<uint64_t>> *a,
    const DstArray<Polynomial<uint64_t>> *b,
    uint8_t* scratch_buf,
    uint32_t d
) {
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

    c_i_fft->ifft(c_i, degree);
}