#pragma once

#include "../../src/entities/dst_array.cuh"
#include "../../src/math/signed_decomposer.cuh"
#include "../../src/entities/polynomial.cuh"

extern "C" __global__ void can_decompose_polynomial(
    const cuda::std::complex<f64> *__restrict__ poly_buf,
    cuda::std::complex<f64> *__restrict__ scratch_buf,
    cuda::std::complex<f64> *__restrict__ o1_buf,
    cuda::std::complex<f64> *__restrict__ o2_buf,
    cuda::std::complex<f64> *__restrict__ o3_buf,
    cuda::std::complex<f64> *__restrict__ o4_buf
) {
    auto degree = PolynomialDegree(2048);
    auto radix = RadixDecomposition(4, 3);

    auto poly = DstArray<Polynomial>::from_ptr(poly_buf);
    auto scratch = DstArray<Polynomial>::from_ptr(scratch_buf);
    auto o1 = DstArray<Polynomial>::from_ptr(o1_buf);
    auto o2 = DstArray<Polynomial>::from_ptr(o2_buf);
    auto o3 = DstArray<Polynomial>::from_ptr(o3_buf);
    auto o4 = DstArray<Polynomial>::from_ptr(o4_buf);

    auto decomp = PolynomialSignedRadixDecomposer(
        poly.nth(blockIdx.x, degree),
        scratch.nth(blockIdx.x, degree),
        radix,
        degree);

    decomp.next(o1.nth(blockIdx.x, degree));
    decomp.next(o2.nth(blockIdx.x, degree));
    decomp.next(o3.nth(blockIdx.x, degree));
    decomp.next(o4.nth(blockIdx.x, degree));
}