#pragma once
#include <cstdint>

#define STACK_ALLOCATOR

template <typename T>
class PerBlockStackAllocation;

/// @brief A per-block scratch allocator overlay on a given global memory buffer.
/// When STACK_ALLOCATOR is defined, this class will dole out allocation in LIFO order;
/// that is it will return memory pointing to the last freed buffer, which is likely to
/// still be cache-resident.
///
/// @remarks To avoid undefined behavior, it should never be the case that an allocation
/// originating at time t outlives any allocation with time < t. That is, allocations should
/// destruct in reverse order of their allocation. Fortunately, this is exactly how RAII
/// and C++ scopes work.
class PerBlockStackAllocator
{
    template <typename T>
    friend class PerBlockStackAllocation;

public:
    __device__ PerBlockStackAllocator() = delete;
    __device__ inline PerBlockStackAllocator(uint8_t *scratch, uint32_t length)
    {
        this->m_per_block_size = length / gridDim.x;

        assert(this->m_per_block_size * gridDim.x == length);

        this->m_scratch = &scratch[blockIdx.x * this->m_per_block_size];
        this->m_next = this->m_scratch;
    }

    /// @brief Allocate and return a T using the given sizing parameters. Each thread in a block must
    /// call this with the same parameter and each thread will receive a pointer to the same buffer.
    /// @tparam T The type to allocate
    /// @tparam U The size parameters to query T with
    /// @param params The size parameters
    /// @return The allocation.
    template <typename T, typename U>
    __device__ PerBlockStackAllocation<T> inline alloc(const U &params)
    {
        uint32_t size = T::size(params);
        uint32_t align = T::align();

        // Align our allocation.
        auto padding = (align - reinterpret_cast<size_t>(m_next) % align) % align;

        // Check we don't overflow our stack.
        assert(&m_next[size + padding] <= &m_scratch[m_per_block_size]);

        auto alloc_ptr = &m_next[padding];
        m_next = &m_next[padding + size];
        
        return PerBlockStackAllocation<T>(this, reinterpret_cast<T *>(alloc_ptr));
    }

private:
    uint8_t *m_next;

    /// A pointer to the base of this block's scratch.
    uint8_t *m_scratch;

    /// @brief number of bytes available per block.
    uint32_t m_per_block_size;
};

template <typename T>
class PerBlockStackAllocation
{
    friend class PerBlockStackAllocator;
public:
    __device__ PerBlockStackAllocation() = delete;
    __device__ PerBlockStackAllocation(const PerBlockStackAllocation &rhs) = delete;
    __device__ PerBlockStackAllocation(const PerBlockStackAllocation &&rhs) = delete;
    __device__ PerBlockStackAllocation<T>& operator=(const PerBlockStackAllocation<T>&) = delete;
    __device__ PerBlockStackAllocation<T>& operator=(const PerBlockStackAllocation<T>&&) = delete;

    __device__ inline T *operator*()
    {
        return m_ptr;
    }

    __device__ inline const T *operator*() const
    {
        return m_ptr;
    }

    __device__ inline T *operator->()
    {
        return m_ptr;
    }

    __device__ inline const T *operator->() const
    {
        return m_ptr;
    }

    __device__ ~PerBlockStackAllocation()
    {
        auto next = min(reinterpret_cast<size_t>(m_allocator->m_next), reinterpret_cast<size_t>(m_ptr));
        m_allocator->m_next = reinterpret_cast<uint8_t *>(next);
    }

private:
    __device__ PerBlockStackAllocation(PerBlockStackAllocator *base, T *ptr) : m_allocator(base), m_ptr(ptr) {}

    PerBlockStackAllocator *m_allocator;
    T *m_ptr;
};

__device__ inline uint32_t get_scratch_size(uint32_t num_blocks)
{
    // 512kB per block is good enough?
    return num_blocks * 512 * 1024;
}

__device__ inline uint32_t get_scratch_size()
{
    return get_scratch_size(gridDim.x);
}

extern "C" __global__ void query_scratch_size_per_block(
    uint32_t *size)
{
    *size = get_scratch_size(1);
}

/// @brief A dynamically sized type buffer.
template <typename T>
class DstBuffer {
public:
    __device__ static inline uint32_t size(uint32_t count) {
        return count * sizeof(T);
    }

    __device__ static inline constexpr size_t align() {
        return alignof(T);
    }

    __device__ inline T *operator*() {
        return data;
    }

    __device__ inline const T *operator*() const {
        return data;
    }

    __device__ inline T& operator[](uint32_t i) {
        return data[i];
    }

    __device__ inline const T& operator[](uint32_t i) const {
        return data[i];
    }

    __device__ inline T* ptr() {
        return data;
    }

    __device__ inline const T* ptr() const {
        return data;
    }
private:
    T data[0];
};
