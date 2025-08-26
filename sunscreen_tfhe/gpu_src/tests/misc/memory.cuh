#pragma once
#include <cuda/std/complex>
#include <cstdint>

#include "../../src/math/primitives.cuh"
#include "../../src/entities/punbuf.cuh"
#include "../../src/entities/scratch.cuh"
#include "../../src/iter_tools.cuh"
#include "../../src/params.cuh"

extern "C" __global__ void can_copy_to_and_from_shared_memory(
    const u32 *__restrict__ input,
    u32 *__restrict__ output
) {
    const u32 N = 2345;
    
    auto s_input = get_fft_scratch();
    auto sptr = reinterpret_cast<u32*>(s_input.as_f64());

    BLOCK_COPY(sptr, &input[N * blockIdx.x], N);
    BLOCK_COPY(&output[N * blockIdx.x], sptr, N);
}

extern "C" __global__ void can_use_scratch(
    const f64 *__restrict__ a,
    const f64 *__restrict__ b,
    f64 *__restrict__ output,
    cuda::std::complex<f64> *__restrict__ scratch_buffer
) {
    const u32 N = 2344;

    auto allocator = PerBlockStackAllocator(scratch_buffer, get_scratch_size());
    auto a_clone = allocator.alloc<DstBuffer>(N);
    auto b_clone = allocator.alloc<DstBuffer>(N);
    f64* a_clone_ptr = (*a_clone).ptr();
    f64* b_clone_ptr = (*b_clone).ptr();

    assert(reinterpret_cast<uintptr_t>(b_clone_ptr) - reinterpret_cast<uintptr_t>(a_clone_ptr) == N * sizeof(cuda::std::complex<f64>) / 2);

    BLOCK_COPY(a_clone_ptr, &a[N * blockIdx.x], N);
    BLOCK_COPY(b_clone_ptr, &b[N * blockIdx.x], N);

    for (u32 i = threadIdx.x; i < N; i += blockDim.x) {
        output[N * blockIdx.x + i] = (a_clone_ptr)[i] + (b_clone_ptr)[i];
    }
}

extern "C" __global__ void can_load_store_ints_to_punbuf(
    const cuda::std::complex<f64>* a,
    cuda::std::complex<f64>* b,
    const u32 len
) {
    const auto a_punbuf = PunBuf::from_ptr(a);
    auto b_punbuf = PunBuf::from_ptr(b);

    BLOCK_FOR_EACH(i, len) {
        b_punbuf.set_u64(i, a_punbuf.get_u64(i));
    }
}

extern "C" __global__ void can_marshal_params(
    LweDef lwe,
    GlweDef glwe,
    RadixDecomposition radix,
    u32 *__restrict__ results
) {
    if (threadIdx.x == 0) {
        results[0] = lwe.size.val;
        results[1] = glwe.log_poly_degree.val;
        results[2] = glwe.size.val;
        results[3] = radix.count.val;
        results[4] = radix.radix_log.val;
    }
}