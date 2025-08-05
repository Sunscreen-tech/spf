#pragma once
#include "../../src/entities/dst.cuh"
#include "../../src/entities/polynomial.cuh"

extern "C" __global__ void can_polynomial_rountrip_fft(
    const Polynomial<uint64_t>* __restrict__ x,
    Polynomial<uint64_t>* __restrict__ y,
    const uint32_t n
) {
    init_scratch();
    const PolynomialDegree degree = PolynomialDegree { n };
    auto tmp = scratch_alloc<PolynomialFft<Complex<double>>>(degree);

    x->fft(*tmp, degree);
    tmp->ifft(y, degree);
}