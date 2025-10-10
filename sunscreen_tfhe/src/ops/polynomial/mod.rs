use std::{
    ops::Mul,
    sync::{Arc, OnceLock},
};

use crate::{
    PlaintextBits, PolynomialDegree, Torus, TorusOps,
    dst::FromMutSlice,
    entities::{DstArray, PolynomialFft, PolynomialFftRef, PolynomialRef},
    scratch::allocate_scratch_ref,
    simd::{VectorOps, complex_mad, complex_msub, complex_mul},
};
use dashmap::DashMap;

use num::{Complex, traits::WrappingSub};
use sunscreen_math::{One, Zero};

fn x_i_cache(degree: PolynomialDegree) -> Arc<DstArray<PolynomialFft<Complex<f64>>>> {
    type PolyCache = DashMap<usize, OnceLock<Arc<DstArray<PolynomialFft<Complex<f64>>>>>>;
    static X_I_CACHE: OnceLock<PolyCache> = OnceLock::new();

    let cache = X_I_CACHE.get_or_init(PolyCache::new);

    cache
        .entry(degree.0)
        .or_default()
        .get_or_init(|| {
            let mut lut = DstArray::<PolynomialFft<Complex<f64>>>::new(2 * degree.0, degree);

            allocate_scratch_ref!(non_fft, PolynomialRef<u64>, (degree));

            for i in 0..2 * degree.0 {
                non_fft.clear();

                if i < degree.0 {
                    non_fft.coeffs_mut()[i] = 1u64;
                } else {
                    non_fft.coeffs_mut()[i - degree.0] = 0u64.wrapping_sub(1);
                }

                // TODO: We can directly fill in the FFT for with higher precision. The
                // input is a Dirac delta, so the FFT is just a sinusoid.
                non_fft.fft(lut.iter_mut(degree).nth(i).unwrap());
            }

            Arc::new(lut)
        })
        .to_owned()
}

/// Multiply a negacyclic polynomial by x^i in the Fourier domain.
///
/// # Panics
/// If result.len() is not a power of 2.
pub fn polynomial_mul_positive_monomial_fft(
    result: &mut PolynomialFftRef<Complex<f64>>,
    x: &PolynomialFftRef<Complex<f64>>,
    i: usize,
) {
    assert!(result.len().is_power_of_two() && !result.is_empty());

    let degree = 2 * result.len();

    let cache = x_i_cache(PolynomialDegree(degree));

    let x_i = cache
        .iter(PolynomialDegree(degree))
        .nth(i % (2 * degree))
        .unwrap();

    complex_mul(result.coeffs_mut(), x_i.coeffs(), x.coeffs());
}

/// Multiply a negacyclic polynomial by x^i in the Fourier domain.
///
/// # Panics
/// If result.len() is not a power of 2.
pub fn polynomial_mad_positive_monomial_fft(
    result: &mut PolynomialFftRef<Complex<f64>>,
    x: &PolynomialFftRef<Complex<f64>>,
    i: usize,
) {
    assert!(result.len().is_power_of_two() && !result.is_empty());

    let degree = 2 * result.len();

    let cache = x_i_cache(PolynomialDegree(degree));

    let x_i = cache
        .iter(PolynomialDegree(degree))
        .nth(i % (2 * degree))
        .unwrap();

    complex_mad(result.coeffs_mut(), x_i.coeffs(), x.coeffs());
}

/// Multiply a negacyclic polynomial by x^i in the Fourier domain.
///
/// # Panics
/// If result.len() is not a power of 2.
pub fn polynomial_msub_positive_monomial_fft(
    result: &mut PolynomialFftRef<Complex<f64>>,
    x: &PolynomialFftRef<Complex<f64>>,
    i: usize,
) {
    assert!(result.len().is_power_of_two() && !result.is_empty());

    let degree = 2 * result.len();

    let cache = x_i_cache(PolynomialDegree(degree));

    let x_i = cache
        .iter(PolynomialDegree(degree))
        .nth(i % (2 * degree))
        .unwrap();

    complex_msub(result.coeffs_mut(), x_i.coeffs(), x.coeffs());
}

/// Multiply a negacyclic polynomial by x^-i in the Fourier domain.
///
/// # Panics
/// If result.len() is not a power of 2.
pub fn polynomial_mul_negative_monomial_fft(
    result: &mut PolynomialFftRef<Complex<f64>>,
    x: &PolynomialFftRef<Complex<f64>>,
    i: usize,
) {
    assert!(result.len().is_power_of_two() && !result.is_empty());

    let degree = 2 * result.len();

    let cache = x_i_cache(PolynomialDegree(degree));

    let x_i = cache
        .iter(PolynomialDegree(degree))
        .nth((2 * degree - i) % (2 * degree))
        .unwrap();

    complex_mul(result.coeffs_mut(), x_i.coeffs(), x.coeffs());
}

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

/// Transform an input polynomial `P[X]` into `P[X^k]`. This accounts for the negacyclic property
/// of `Z_q[X]/(X^N + 1)`.
///
/// # Panics
/// If `p_k` and `p` are not the same length.
/// If p.len() is not a power of 2.
pub fn polynomial_pow_k<S, T>(p_k: &mut PolynomialRef<S>, p: &PolynomialRef<S>, k: usize)
where
    S: Clone + Copy + Mul<T, Output = S>,
    T: Clone + Copy + One + Zero + WrappingSub<Output = T>,
{
    assert_eq!(p.len(), p_k.len());
    assert!(p.len().is_power_of_two());

    let degree = p.len();
    let one = T::one();
    let minus_one = T::zero().wrapping_sub(&one);

    for i in 0..degree {
        let i_k = i * k % degree;

        // If we land on an even multiple of degree, then we're not in a negacyclic wrapping. Else,
        // we need to multiply by -1.
        let sign = if ((i * k) / degree).is_multiple_of(2) {
            one
        } else {
            minus_one
        };

        p_k.coeffs_mut()[i_k] = p.coeffs()[i] * sign;
    }
}

/// Logical right-shift all the coefficients by `n` places. Rounds by adding
/// the `n + 1`th place.
pub fn polynomial_shr_round<S>(y: &mut PolynomialRef<S>, x: &PolynomialRef<S>, n: u32)
where
    S: Clone + VectorOps,
{
    S::vector_shr_round(y.coeffs_mut(), x.coeffs(), n);
}

#[cfg(test)]
mod tests {
    use num::Zero;
    use rand::{RngCore, rng};

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

    #[test]
    fn can_polynomial_shift_round() {
        let poly = Polynomial::<u64>::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8]);
        let mut result = Polynomial::zero(8);

        polynomial_shr_round(&mut result, &poly, 2);

        assert_eq!(result, Polynomial::new(&[0, 0, 1, 1, 1, 1, 2, 2]));
    }

    #[test]
    fn can_multiply_positive_monomial_fft() {
        // Use small-ish coefficients so we don't have to deal with roundoff in our
        // analysis.
        let poly = Polynomial::new(
            &(0..2048)
                .map(|_| rng().next_u64() % (0x1 << 16))
                .collect::<Vec<_>>(),
        );

        let mut result = PolynomialFft::new(&vec![Complex::zero(); 1024]);

        let mut poly_fft = result.clone();
        poly.fft(&mut poly_fft);

        for i in 0..4096 {
            polynomial_mul_positive_monomial_fft(&mut result, &poly_fft, i);

            let mut actual = Polynomial::<u64>::zero(2048);
            result.ifft(&mut actual);

            let mut expected = poly.map(|x| Torus::from(*x));

            expected.mul_by_monomial_negacyclic(i as isize);
            let expected = expected.map(|x| x.inner());

            // Should get same answer as non-fft computation.
            assert_eq!(actual.coeffs(), expected.coeffs())
        }
    }

    #[test]
    fn can_multiply_negative_monomial_fft() {
        // Use small-ish coefficients so we don't have to deal with roundoff in our
        // analysis.
        let poly = Polynomial::new(
            &(0..2048)
                .map(|_| rng().next_u64() % (0x1 << 16))
                .collect::<Vec<_>>(),
        );

        let mut result = PolynomialFft::new(&vec![Complex::zero(); 1024]);

        let mut poly_fft = result.clone();
        poly.fft(&mut poly_fft);

        for i in 0..4096 {
            polynomial_mul_negative_monomial_fft(&mut result, &poly_fft, i);

            let mut actual = Polynomial::<u64>::zero(2048);
            result.ifft(&mut actual);

            let mut expected = poly.map(|x| Torus::from(*x));

            expected.mul_by_monomial_negacyclic(-(i as isize));
            let expected = expected.map(|x| x.inner());

            // Should get same answer as non-fft computation.
            assert_eq!(actual.coeffs(), expected.coeffs())
        }
    }
}
