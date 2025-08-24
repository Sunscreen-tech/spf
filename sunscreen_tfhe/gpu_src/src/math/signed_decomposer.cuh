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
        const PolynomialDegree d) : m_radix(radix), m_poly(poly), m_scratch(scratch), m_cur_level(0), m_degree(d)
    { }

    __device__ inline void next(Polynomial result)
    {
        assert(m_cur_level < m_radix.count.val);

        BLOCK_FOR_EACH(i, m_degree.val)
        {
            // Round the input.
            u64 coeff = m_poly.coeffs().get_u64(i);
            u32 initial_shift = Unsigned<u64>::BITS - m_radix.radix_log.val * m_radix.count.val;
            u32 round_bit = (coeff >> (initial_shift - 1)) & 0x1;
            u64 s = (coeff >> initial_shift) + round_bit;
            
            u64 mask = (0x1 << m_radix.radix_log.val) - 1;

            // This results in recomputation between iterations, but the number of
            // levels is usually small and we want to avoid needing extra memory.
            for (u32 i = 0; i <= m_cur_level; i++) {
                u64 digit = s & mask;
                s >>= m_radix.radix_log.val;
                u64 carry = digit >> (m_radix.radix_log.val - 1);
                m_scratch.coeffs().set_u64(i, s + carry);
                s = digit - (carry << m_radix.radix_log.val);
            }
        }

        m_cur_level++;
    }

private:
    RadixDecomposition m_radix;
    PolynomialDegree m_degree;
    Polynomial m_poly;
    Polynomial m_scratch;
    u32 m_cur_level;
};
