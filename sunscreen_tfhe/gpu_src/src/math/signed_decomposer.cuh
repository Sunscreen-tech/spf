#pragma once
#include <cstdint>

#include "../iter_tools.cuh"
#include "../entities/polynomial.cuh"
#include "../params.cuh"

template <typename T>
class PolynomialSignedRadixDecomposer
{
public:
    PolynomialSignedRadixDecomposer() = delete;
    PolynomialSignedRadixDecomposer(const PolynomialSignedRadixDecomposer &rhs) = delete;
    PolynomialSignedRadixDecomposer operator=(const PolynomialSignedRadixDecomposer &rhs) = delete;

    __device__ inline PolynomialSignedRadixDecomposer(
        const Polynomial<T> *poly,
        Polynomial<T> *scratch,
        const RadixDecomposition radix,
        const PolynomialDegree d) : m_radix(radix), m_scratch(scratch), m_cur_level(0), m_degree(d)
    {
        // Store a rounded copy of each coefficient in scratch
        BLOCK_FOR_EACH(i, d.val)
        {
            T coeff = poly->coeffs()[i];
            u32 shift = Unsigned<T>::BITS - radix.radix_log.val * radix.count.val;
            u32 round_bit = (coeff >> (shift - 1)) & 0x1;

            scratch->coeffs()[i] = (coeff >> shift) + round_bit;
        }
    }

    __device__ inline void next(Polynomial<T> *result)
    {
        assert(m_cur_level < m_radix.count.val);

        BLOCK_FOR_EACH(i, m_degree.val)
        {
            T mask = (0x1 << m_radix.radix_log.val) - 1;
            T s = m_scratch->coeffs()[i];

            T digit = s & mask;
            s >>= m_radix.radix_log.val;
            T carry = digit >> (m_radix.radix_log.val - 1);
            m_scratch->coeffs()[i] = s + carry;
            result->coeffs()[i] = digit - (carry << m_radix.radix_log.val);
        }

        m_cur_level++;
    }

private:
    RadixDecomposition m_radix;
    PolynomialDegree m_degree;
    Polynomial<T> *m_scratch;
    u32 m_cur_level;
};
