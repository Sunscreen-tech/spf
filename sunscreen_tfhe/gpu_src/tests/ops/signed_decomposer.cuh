#pragma once
#include <cstdint>

#include "../../src/entities/dst_array.cuh"
#include "../../src/math/signed_decomposer.cuh"
#include "../../src/entities/polynomial.cuh"

extern "C" __global__ void can_decompose_polynomial(
    const DstArray<Polynomial<uint64_t>> *__restrict__ poly,
    DstArray<Polynomial<uint64_t>> *__restrict__ scratch,
    DstArray<Polynomial<uint64_t>> *__restrict__ o1,
    DstArray<Polynomial<uint64_t>> *__restrict__ o2,
    DstArray<Polynomial<uint64_t>> *__restrict__ o3,
    DstArray<Polynomial<uint64_t>> *__restrict__ o4
) {
    auto degree = PolynomialDegree(2048);
    auto radix = RadixDecomposition(4, 3);

    auto decomp = PolynomialSignedRadixDecomposer(
        poly->nth(blockIdx.x, degree),
        scratch->nth(blockIdx.x, degree),
        radix,
        degree);

    decomp.next(o1->nth(blockIdx.x, degree));
    decomp.next(o2->nth(blockIdx.x, degree));
    decomp.next(o3->nth(blockIdx.x, degree));
    decomp.next(o4->nth(blockIdx.x, degree));
}