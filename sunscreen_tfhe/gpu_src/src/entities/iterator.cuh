#pragma once

template <typename T, typename U>
class DstIterator
{
public:
    DstIterator(T *start, uint32_t stride)
        : m_cur(start),
          m_stride(stride) {}

    DstIterator &operator++()
    {
        return m_cur += m_stride;
    }

    bool operator==(const DstIterator &other) {
        return other.m_cur == m_cur;
    }

    bool operator!=(const DstIterator &other) {
        return !(*this == other);
    }

    U* operator*() {
        reinterpret_cast<U *>(m_cur)
    }

    using different_type = U*;
    using value_type = U*;
    using pointer = const U**;
    using reference = const U *&;
    using iterator_category = std::forward_iterator_tag;

private:
    T *m_cur;
    uint32_t m_stride;
};