#pragma once
#include "../../src/entities/dst_array.cuh"
#include "../../src/entities/polynomial.cuh"
#include "../../src/entities/scratch.cuh"
#include "../../src/ops/polynomial.cuh"

extern "C" __global__ void can_polynomial_rountrip_fft(
    const Polynomial<uint64_t>* __restrict__ x,
    Polynomial<uint64_t>* __restrict__ y,
    uint8_t* scratch_buf,
    const uint32_t n
) {
    auto degree = PolynomialDegree(n);
    auto allocator = PerBlockStackAllocator(scratch_buf, get_scratch_size());
    auto tmp = allocator.alloc<PolynomialFft<Complex<double>>>(degree);

    x->fft(*tmp, degree);
    tmp->ifft(y, degree);
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