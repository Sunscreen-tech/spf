#pragma once
#include <cstdint>

template <typename T>
class DstAllocation;

const size_t kScratchSize = 63 * 1024 * 1024;
static __shared__ uint8_t SCRATCH[kScratchSize];
static __shared__ uint8_t *SCRATCH_BOTTOM;

void init_scratch()
{
    if (threadIdx.x == 0)
    {
        SCRATCH_BOTTOM = SCRATCH;
    }

    __syncthreads();
}

template <typename T>
class ScratchAllocation
{
private:
    uint8_t *prev;
    uint8_t *cur;

public:
    T *operator->()
    {
        return reinterpret_cast<T *>(cur);
    }

    const T *operator->() const
    {
        return reinterpret_cast<const T *>(cur);
    }

    ScratchAllocation(uint8_t* prev, uint8_t* cur): prev(prev), cur(cur) {}

    ~ScratchAllocation()
    {
        if (threadIdx.x == 0)
        {
            SCRATCH_BOTTOM = reinterpret_cast<uint8_t*>(min(reinterpret_cast<size_t>(prev), reinterpret_cast<size_t>(SCRATCH_BOTTOM)));
        }

        __syncthreads();
    }
};

template <typename T, typename V>
ScratchAllocation<T> scratch_alloc(const V &size_info)
{
    __shared__ uint8_t *prev;
    __shared__ uint8_t *cur;

    if (threadIdx.x == 0)
    {
        size_t align = T::align();
        size_t size = T::size(size_info);

        prev = SCRATCH_BOTTOM;
        SCRATCH_BOTTOM += (align - reinterpret_cast<size_t>(SCRATCH_BOTTOM) % align) % align;
        cur = SCRATCH_BOTTOM;
        SCRATCH_BOTTOM += size;
    }

    __syncthreads();

    return ScratchAllocation<T>(cur, prev);
}