use std::ops::Mul;

use crate::{PlaintextBits, Torus, TorusOps, entities::PolynomialRef, simd::VectorOps};

use num::traits::WrappingSub;
use sunscreen_math::Zero;

/// Encode a polynomial for encryption.
///
/// # Remarks
/// This amounts to left shifting each coefficient by `S::BITS - plain_bits`.
/// We encode messages because noise grows in the lower bits
/// (scheme parameters willing) as homomorphic computation unfolds.
///
/// This operation is idempotent; clearing result beforehand is not necessary.
///
/// # Panics
/// If `result.len() != msg.len()`
pub fn encode_polynomial<S>(
    result: &mut PolynomialRef<Torus<S>>,
    msg: &PolynomialRef<S>,
    plain_bits: PlaintextBits,
) where
    S: TorusOps,
{
    assert_eq!(result.len(), msg.len());

    result
        .coeffs_mut()
        .iter_mut()
        .zip(msg.coeffs().iter())
        .for_each(|(e, m)| *e = Torus::encode(*m, plain_bits));
}

/// Decode a polynomial.
///
/// # Remarks
/// This amounts to right shifting each coefficient by `S::BITS - plain_bits` places.
/// This operation is idempotent
pub fn decode_polynomial<S>(
    result: &mut PolynomialRef<S>,
    msg: &PolynomialRef<Torus<S>>,
    plain_bits: PlaintextBits,
) where
    S: TorusOps,
{
    assert_eq!(result.len(), msg.len());

    result
        .coeffs_mut()
        .iter_mut()
        .zip(msg.coeffs().iter())
        .for_each(|(e, m)| *e = Torus::decode(m, plain_bits));
}

/// Transform a input polynomial `P[X]` into `P[X^k]`. This accounts for the negacyclic property
/// of `Z_q[X]/(X^N + 1)`.
///
/// # Panics
/// If `p_k` and `p` are not the same length.
/// If p.len() is not a power of 2.
pub fn polynomial_pow_k<S, T>(p_k: &mut PolynomialRef<S>, p: &PolynomialRef<S>, k: usize)
where
    S: Clone + Copy + Mul<T, Output = S>,
    T: Clone + Copy + sunscreen_math::One + Zero + WrappingSub<Output = T>,
{
    assert_eq!(p.len(), p_k.len());
    assert!(p.len().is_power_of_two());

    let degree = p.len();
    let one = T::one();
    let minus_one = <T as sunscreen_math::Zero>::zero().wrapping_sub(&one);

    for i in 0..degree {
        let i_k = i * k % degree;

        // If we land on an even multiple of degree, then we're not in a negacyclic wrapping. Else,
        // we need to multiply by -1.
        let sign = if ((i * k) / degree) % 2 == 0 {
            one
        } else {
            minus_one
        };

        p_k.coeffs_mut()[i_k] = p.coeffs()[i] * sign;
    }
}

/// Logical right-shift all the coefficients by `n` places.
pub fn polynomial_shr<S>(y: &mut PolynomialRef<S>, x: &PolynomialRef<S>, n: u32)
where
    S: Clone + VectorOps,
{
    S::vector_shr(y.coeffs_mut(), x.coeffs(), n);
}

#[cfg(test)]
mod tests {
    use crate::entities::Polynomial;

    use super::*;

    #[test]
    fn can_encode_polynomial() {
        let len = 1024u64;
        let plain_bits = PlaintextBits(4);

        let polynomial = Polynomial::new(&(0..len).map(|x| x % 8).collect::<Vec<_>>());
        let mut encoded = Polynomial::zero(len as usize);

        encode_polynomial(&mut encoded, &polynomial, plain_bits);

        for (i, c) in encoded.coeffs().iter().enumerate() {
            let expected = Torus::encode(i as u64 % 8, plain_bits);

            assert_eq!(*c, expected);
        }
    }
    #[test]
    fn can_decode_polynomial() {
        let len = 1024u64;
        let plain_bits = PlaintextBits(4);

        let polynomial = Polynomial::new(&(0..len).map(|x| x % 8).collect::<Vec<_>>());
        let mut encoded = Polynomial::zero(len as usize);

        encode_polynomial(&mut encoded, &polynomial, plain_bits);

        let mut decoded = Polynomial::zero(len as usize);

        decode_polynomial(&mut decoded, &encoded, plain_bits);

        assert_eq!(decoded, polynomial);
    }

    #[test]
    fn can_polynomial_pow_k() {
        let mut polynomial = Polynomial::<u64>::zero(128);
        polynomial.coeffs_mut()[0] = 17;
        polynomial.coeffs_mut()[6] = 19;
        polynomial.coeffs_mut()[26] = 52;
        polynomial.coeffs_mut()[93] = 45;

        let mut output = Polynomial::<u64>::zero(128);

        polynomial_pow_k::<_, u64>(&mut output, &polynomial, 33);

        for i in 0..128 {
            let expected = match i {
                0 => 17,
                70 => 0.wrapping_sub(&19),
                90 => 52,
                125 => 0.wrapping_sub(&45),
                _ => 0,
            };

            assert_eq!(output.coeffs()[i], expected);
        }
    }
}
