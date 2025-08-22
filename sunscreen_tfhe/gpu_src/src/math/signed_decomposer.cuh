#pragma once
#include <cstdint>

#include "../iter_tools.cuh"
#include "../entities/polynomial.cuh"
#include "../params.cuh"

class PolynomialSignedRadixDecomposer
{
public:
    PolynomialSignedRadixDecomposer() = delete;
    PolynomialSignedRadixDecomposer(const PolynomialSignedRadixDecomposer &rhs) = delete;
    PolynomialSignedRadixDecomposer operator=(const PolynomialSignedRadixDecomposer &rhs) = delete;

    __device__ inline PolynomialSignedRadixDecomposer(
        const Polynomial poly,
        Polynomial scratch,
        const RadixDecomposition radix,
        const PolynomialDegree d) : m_radix(radix), m_scratch(scratch), m_cur_level(0), m_degree(d)
    {
        // Store a rounded copy of each coefficient in scratch
        BLOCK_FOR_EACH(i, d.val)
        {
            u64 coeff = poly.coeffs().get_u64(i);
            u32 shift = Unsigned<u64>::BITS - radix.radix_log.val * radix.count.val;
            u32 round_bit = (coeff >> (shift - 1)) & 0x1;

            scratch.coeffs().set_u64(i, (coeff >> shift) + round_bit);
        }
    }

    __device__ inline void next(Polynomial result)
    {
        assert(m_cur_level < m_radix.count.val);

        BLOCK_FOR_EACH(i, m_degree.val)
        {
            u64 mask = (0x1 << m_radix.radix_log.val) - 1;
            u64 s = m_scratch.coeffs().get_u64(i);

            u64 digit = s & mask;
            s >>= m_radix.radix_log.val;
            u64 carry = digit >> (m_radix.radix_log.val - 1);
            m_scratch.coeffs().set_u64(i, s + carry);
            result.coeffs().set_u64(i, digit - (carry << m_radix.radix_log.val));
        }

        m_cur_level++;
    }

private:
    RadixDecomposition m_radix;
    PolynomialDegree m_degree;
    Polynomial m_scratch;
    u32 m_cur_level;
};
