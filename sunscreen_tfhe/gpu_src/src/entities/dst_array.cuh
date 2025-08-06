#pragma once

/// @brief An array of DSTs with methods for retrieving inner DSTs.
/// @tparam T The item type
template <typename T>
class DstArray {
public:
    DstArray() = delete;

    template <typename V>
    __device__ inline T *nth(uint32_t i, const V& size_info) {
        return reinterpret_cast<T *>(&data[i * T::size(size_info)]);
    }

    template <typename V>
    __device__ inline const T *nth(uint32_t i, const V& size_info) const {
        return reinterpret_cast<const T *>(&data[i * T::size(size_info)]);
    }

private:
    uint8_t data[0];
};
