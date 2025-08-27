#pragma once
#include <cuda/std/complex>
#include <cstdint>

#include "../math/math.cuh"
#include "../math/primitives.cuh"

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
    __device__ PerBlockStackAllocator(const PerBlockStackAllocator& rhs) = delete;
    __device__ PerBlockStackAllocator(const PerBlockStackAllocator&& rhs) = delete;
    __device__ PerBlockStackAllocator operator=(const PerBlockStackAllocator& rhs) = delete;

    __device__ inline PerBlockStackAllocator(cuda::std::complex<f64> *scratch, u32 length, bool is_local = false)
    {
        this->m_per_block_size = is_local
            ? length
            : length / gridDim.x;

        if (!is_local) {
            assert(this->m_per_block_size * gridDim.x == length);
        }

        this->m_scratch = is_local
            ? scratch
            : &scratch[blockIdx.x * this->m_per_block_size];
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
        // Size is in complex<f64> (16-byte) values
        u32 size = T::size(params);

        // Check we don't overflow our stack.
        assert(&m_next[size] <= &m_scratch[m_per_block_size]);

        auto alloc_ptr = m_next;
        m_next = &m_next[size];

        return PerBlockStackAllocation<T>(this, alloc_ptr, size);
    }

private:
    cuda::std::complex<f64> *m_next;

    /// A pointer to the base of this block's scratch.
    cuda::std::complex<f64> *m_scratch;

    /// @brief number of bytes available per block.
    u32 m_per_block_size;
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

    __device__ constexpr inline T operator*()
    {
        return T::from_ptr(m_ptr);
    }

    __device__ constexpr inline const T operator*() const
    {
        return T::from_ptr(m_ptr);
    }

    __device__ constexpr inline const T get() {
        return T::from_ptr(m_ptr);
    }

    __device__ constexpr inline const T get() const {
        return T::from_ptr(m_ptr);
    }

    __device__ ~PerBlockStackAllocation()
    {
        auto next = min(reinterpret_cast<uintptr_t>(m_allocator->m_next), reinterpret_cast<uintptr_t>(m_ptr));
        m_allocator->m_next = reinterpret_cast<cuda::std::complex<f64> *>(next);
    }

    __device__ inline void clear() {
        for (u32 i = threadIdx.x; i < m_size; i += blockDim.x) {
            m_ptr[i] = cuda::std::complex<f64>(0.0, 0.0);
        }
    }
private:
    __device__ constexpr inline explicit PerBlockStackAllocation(PerBlockStackAllocator *base, cuda::std::complex<f64> *ptr, u32 size) : m_allocator(base), m_ptr(ptr), m_size(size) {}

    PerBlockStackAllocator *m_allocator;
    cuda::std::complex<f64> *m_ptr;
    u32 m_size;
};

/// @brief Returns the size in cuda::std::complex<f64> items.
/// @param num_blocks 
/// @return
__device__ inline u32 get_scratch_size(u32 num_blocks)
{
    // 512kB per block is good enough?
    return num_blocks * 512 * 1024 / sizeof(cuda::std::complex<f64>);
}

__device__ inline u32 get_scratch_size()
{
    return get_scratch_size(gridDim.x);
}

extern "C" __global__ void query_scratch_size_per_block(
    u32 *size)
{
    *size = get_scratch_size(1);
}

#ifdef TEST

/// @brief A dynamically sized type buffer. Stores f64 values. Used for testing
class DstBuffer {
public:
    DstBuffer() = delete;
    __device__ explicit constexpr inline DstBuffer(PunBuf data): m_data(data) { }

    __device__ constexpr static inline u32 size(u32 count) {
        return count / 2;
    }

    __device__ constexpr inline f64 *operator*() {
        return m_data.as_f64();
    }

    __device__ constexpr inline const f64 *operator*() const {
        return m_data.as_f64();
    }

    __device__ constexpr inline f64& operator[](u32 i) {
        return m_data.as_f64()[i];
    }

    __device__ constexpr inline const f64& operator[](u32 i) const {
        return m_data.as_f64()[i];
    }

    __device__ constexpr inline f64 *ptr() {
        return m_data.as_f64();
    }

    __device__ constexpr inline const f64 *ptr() const {
        return m_data.as_f64();
    }
   
    __device__ static constexpr inline DstBuffer from_ptr(cuda::std::complex<f64> *ptr) {
        return DstBuffer(PunBuf::from_ptr(ptr));
    }

    __device__ static constexpr inline const DstBuffer from_ptr(const cuda::std::complex<f64> *ptr) {
        return DstBuffer(PunBuf::from_ptr(ptr));
    }
private:
    PunBuf m_data;
};

#endif