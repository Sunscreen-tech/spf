#pragma once

#include "../../src/entities/punbuf.cuh"
#include "../../src/entities/scratch.cuh"
#include "../../src/math/math.cuh"
#include "../../src/math/fft/negacyclic.cuh"
#include "../../src/math/fft/fft.cuh"

extern "C" __global__ void can_apply_twist(
    const f64 *__restrict__ input,
    cuda::std::complex<f64> *__restrict__ output,
    u32 n
) {
    auto scratch = get_shared_allocator(32 * 1024);
    auto punbuf = scratch.alloc<PunBuf>(n);

    BLOCK_COPY((*punbuf).as_f64(), &input[blockIdx.x * n], n);

    apply_twist(*punbuf, n);

    BLOCK_COPY(&output[blockIdx.x * n / 2], (*punbuf).as_complex(), n / 2);
}

extern "C" __global__ void can_remove_twist(
    const cuda::std::complex<f64> *__restrict__ input,
    f64 *__restrict__ output,
    u32 n
) {
    auto scratch = get_shared_allocator(32 * 1024);
    auto punbuf = scratch.alloc<PunBuf>(n);

    BLOCK_COPY((*punbuf).as_complex(), &input[blockIdx.x * n / 2], n / 2);

    remove_twist(*punbuf, n);

    BLOCK_COPY(&output[blockIdx.x * n], (*punbuf).as_f64(), n);
}