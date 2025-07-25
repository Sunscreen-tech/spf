#include <cstdint>

extern "C" __global__ void vector_add(const float* a, const float* b, float* c, uint32_t len) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;

    if (tid < len) {
        c[tid] = a[tid] + b[tid];
    }
}