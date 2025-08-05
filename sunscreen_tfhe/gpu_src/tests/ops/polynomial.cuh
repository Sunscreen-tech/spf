#pragma once
#include "../../src/entities/polynomial.cuh"
#include "../../src/entities/scratch.cuh"

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