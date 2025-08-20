#pragma once
#include <cstdint>

#include "../../src/math/primitives.cuh"
#include "../../src/entities/punbuf.cuh"
#include "../../src/entities/scratch.cuh"
#include "../../src/iter_tools.cuh"

extern "C" __global__ void can_copy_to_and_from_shared_memory(
    const uint32_t *__restrict__ input,
    uint32_t *__restrict__ output
) {
    const uint32_t N = 2345;
    __shared__ uint32_t s_input[N];
    
    BLOCK_COPY(s_input, &input[N * blockIdx.x], N);
    BLOCK_COPY(&output[N * blockIdx.x], s_input, N);
}

extern "C" __global__ void can_use_scratch(
    const uint32_t *__restrict__ a,
    const uint32_t *__restrict__ b,
    uint32_t *__restrict__ output,
    uint8_t *__restrict__ scratch_buffer
) {
    const uint32_t N = 2345;

    auto allocator = PerBlockStackAllocator(scratch_buffer, get_scratch_size());
    auto a_clone = allocator.alloc<DstBuffer<uint32_t>>(N);
    auto b_clone = allocator.alloc<DstBuffer<uint32_t>>(N);
    uint32_t* a_clone_ptr = a_clone->ptr();
    uint32_t* b_clone_ptr = b_clone->ptr();

    assert(reinterpret_cast<size_t>(b_clone_ptr) - reinterpret_cast<size_t>(a_clone_ptr) == N * sizeof(uint32_t));

    BLOCK_COPY(a_clone_ptr, &a[N * blockIdx.x], N);
    BLOCK_COPY(b_clone_ptr, &b[N * blockIdx.x], N);

    for (uint32_t i = threadIdx.x; i < N; i += blockDim.x) {
        output[N * blockIdx.x + i] = (a_clone_ptr)[i] + (b_clone_ptr)[i];
    }
}

extern "C" __global__ void can_load_store_ints_to_punbuf(
    const std::complex<f64>* a,
    std::complex<f64>* b,
    const u32 len
) {
    const auto a_punbuf = PunBuf::from_ptr(a);
    auto b_punbuf = PunBuf::from_ptr(b);

    BLOCK_FOR_EACH(i, len) {
        b_punbuf.set_u64(i, a_punbuf.get_u64(i));
    }
}