#pragma once

#include <cstdint>

#include "iterator.cuh"
#include "polynomial.cuh"
#include "../params.cuh"

template <typename T>
class GlweCiphertext
{
public:
    class Iter {
        GlweDef m_params;
        T* m_base;
        bool m_include_b;
    public:
        Iter(const GlweDef &params, T* base, bool include_b): m_params(params), m_base(base), m_include_b(include_b) { }    

        __device__ inline DstIterator<T, Polynomial<T>> begin() {
            return DstIterator(m_base, 1 << m_params.log_polynomial_degree)
        }

        __device__ inline DstIterator<T, Polynomial<T>> end() {
            int32_t num_polys = m_include_b
                ? m_params.size + 1
                : m_params.size;

            return DstIterator(&m_base[num_polys * m_params.polynomial_degree()])
        }
    };

    GlweCiphertext() = delete;

    __device__ inline uint32_t size_elems(const GlweDef &params) {
        return (1 << params.polynomial_degree()) * params.size;
    }

    __device__ inline uint32_t size(const GlweDef &params)
    {
        return sizeof(T) * size_elems(params);
    }

    __device__ constexpr inline size_t align()
    {
        return alignof(T);
    }

    __device__ inline Iter a(GlweDef &glwe) {
        return Iter(glwe, data, false);
    }

    __device__ inline Iter a_b(GlweDef &glwe) {
        return Iter(glwe, data, true);
    }

private:
    T data[0];
};

template <typename T>
class GlweCiphertextFft
{
};