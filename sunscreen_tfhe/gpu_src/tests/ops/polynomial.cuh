#pragma once
#include "../../src/entities/polynomial.cuh"

extern "C" __global__ void can_polynomial_rountrip_fft(
    const Polynomial<uint64_t>* __restrict__ x,
    const Polynomial<uint64_t>* __restrict__ y,
    const uint32_t degree
) {

}