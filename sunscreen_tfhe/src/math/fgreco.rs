use std::{
    fmt::{Binary, LowerHex, UpperHex},
    ops::{Add, BitAnd, BitAndAssign, BitOr, BitOrAssign, Mul, Not, Shl, Shr, Sub},
};

use bytemuck::{Pod, Zeroable};
use num::{
    Bounded,
    traits::{WrappingAdd, WrappingMul, WrappingNeg, WrappingShl, WrappingShr, WrappingSub},
};
use rand::{Rng, rng};
use rand_distr::Normal;
use sunscreen_math::{
    BarrettConfig, One, Zero,
    ring::{BarrettBackend, Zq},
};

use crate::{
    Encoding, FromF64, FromU64, NumBits, Random, ReinterpretAsSigned, ToF64, ToU64, TorusOps,
    simd::VectorOps,
};

/// The modulus used for the field used by Greco.
pub const GRECO_MODULUS: u64 = 6943179709095039;

#[derive(BarrettConfig)]
#[barrett_config(modulus = "6943179709095039", num_limbs = 1)]
struct BarrettConfig;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
/// The finite field used in the Greco proof system, which allows generating proofs of encryption.
pub struct FGreco(Zq<1, BarrettBackend<1, BarrettConfig>>);

impl ToF64 for FGreco {
    fn to_f64(self) -> f64 {
        unimplemented!()
    }
}

impl ReinterpretAsSigned for FGreco {
    type Output = Self;

    fn reinterpret_as_signed(self) -> Self::Output {
        unimplemented!()
    }
}

impl FromF64 for FGreco {
    fn from_f64(x: f64) -> Self {
        unimplemented!()
    }
}

impl ToU64 for FGreco {
    fn to_u64(self) -> u64 {
        unimplemented!()
    }
}

impl Zero for FGreco {
    fn zero() -> Self {
        Self(Zq::zero())
    }

    fn vartime_is_zero(&self) -> bool {
        self.0.vartime_is_zero()
    }
}

impl One for FGreco {
    fn one() -> Self {
        Self(Zq::one())
    }
}

impl VectorOps for FGreco {
    fn vector_add(c: &mut [Self], a: &[Self], b: &[Self]) {
        unimplemented!()
    }

    fn vector_mod_pow2_q_f64(c: &mut [Self], a: &[f64], log2_q: u64) {
        unimplemented!()
    }

    fn vector_next_decomp(c: &mut [Self], a: &mut [Self], radix_log: usize) {
        unimplemented!()
    }

    fn vector_scalar_mad(c: &mut [Self], a: &[Self], s: Self) {
        unimplemented!()
    }

    fn vector_shr_round(c: &mut [Self], a: &[Self], n: u32) {
        unimplemented!()
    }

    fn vector_sub(c: &mut [Self], a: &[Self], b: &[Self]) {
        unimplemented!()
    }
}

unsafe impl Zeroable for FGreco {}
unsafe impl Pod for FGreco {}

impl Shl<usize> for FGreco {
    type Output = Self;

    fn shl(self, rhs: usize) -> Self::Output {
        unimplemented!()
    }
}

impl Shr<usize> for FGreco {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        unimplemented!()
    }
}

impl WrappingShl for FGreco {
    fn wrapping_shl(&self, rhs: u32) -> Self {
        unimplemented!()
    }
}

impl WrappingShr for FGreco {
    fn wrapping_shr(&self, rhs: u32) -> Self {
        unimplemented!()
    }
}

impl FromU64 for FGreco {
    fn from_u64(val: u64) -> Self {
        unimplemented!()
    }
}

impl Mul<Self> for FGreco {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl WrappingMul for FGreco {
    fn wrapping_mul(&self, v: &Self) -> Self {
        *self * *v
    }
}

impl Add<Self> for FGreco {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl WrappingAdd for FGreco {
    fn wrapping_add(&self, v: &Self) -> Self {
        *self + *v
    }
}

impl Sub<Self> for FGreco {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl WrappingSub for FGreco {
    fn wrapping_sub(&self, v: &Self) -> Self {
        *self - *v
    }
}

impl WrappingNeg for FGreco {
    fn wrapping_neg(&self) -> Self {
        Self::zero() - *self
    }
}

impl Bounded for FGreco {
    fn min_value() -> Self {
        Self::zero()
    }

    fn max_value() -> Self {
        Self(Zq::from(GRECO_MODULUS) - Zq::one())
    }
}

impl BitOrAssign for FGreco {
    fn bitor_assign(&mut self, rhs: Self) {
        unimplemented!()
    }
}

impl BitAndAssign for FGreco {
    fn bitand_assign(&mut self, rhs: Self) {
        unimplemented!()
    }
}

impl Not for FGreco {
    type Output = Self;

    fn not(self) -> Self::Output {
        unimplemented!()
    }
}

impl BitOr for FGreco {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        unimplemented!()
    }
}

impl BitAnd for FGreco {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        unimplemented!()
    }
}

impl UpperHex for FGreco {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unimplemented!()
    }
}

impl LowerHex for FGreco {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unimplemented!()
    }
}

impl Binary for FGreco {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unimplemented!()
    }
}

impl Default for FGreco {
    fn default() -> Self {
        Self::zero()
    }
}

impl Random for FGreco {
    fn uniform() -> Self {
        let dist = rand_distr::Uniform::new(0, GRECO_MODULUS).unwrap();

        Self(Zq::from(rng().sample(dist)))
    }

    fn normal<F>(std: crate::rand::Stddev, sampler: F) -> Self
    where
        F: FnOnce(&rand_distr::Normal<f64>) -> f64,
    {
        let dist =
            Normal::new(0., std.0).expect("Standard deviation must be finite and non-negative");
        let sample = sampler(&dist);

        let e = f64::round(sample * GRECO_MODULUS as f64) as i64;

        let pos = FGreco::zero() + FGreco::from(e.unsigned_abs());
        let neg = FGreco::zero() - FGreco::from(e.unsigned_abs());

        if e < 0 { neg } else { pos }
    }

    fn binary() -> Self {
        let dist = rand_distr::Uniform::new(0, 2).unwrap();

        Self(Zq::from(rng().sample(dist)))
    }
}

impl Encoding for FGreco {
    fn decode(&self, plaintext_bits: crate::PlaintextBits) -> Self {
        let val = (self.0.val.as_words()[0] as u128) << plaintext_bits.0;
        let round = (GRECO_MODULUS >> plaintext_bits.0 as u64) as u128;
        let val = val + round;

        Self(Zq::from((val / GRECO_MODULUS as u128) as u64))
    }

    fn encode(&self, plaintext_bits: crate::PlaintextBits) -> Self {
        Self(self.0 * Zq::from(GRECO_MODULUS / (plaintext_bits.0 as u64 + 1)))
    }
}

impl TorusOps for FGreco {}

impl NumBits for FGreco {
    /// This is a hack. Don't use any code paths that need this.
    const BITS: u32 = 53;
}

impl From<u64> for FGreco {
    fn from(value: u64) -> Self {
        Self(Zq::from(value))
    }
}

impl Into<u64> for FGreco {
    fn into(self) -> u64 {
        self.0.val.as_words()[0]
    }
}

impl FGreco {
    /// Convert this field element to a [`u64`]`.
    pub fn to_u64(&self) -> u64 {
        self.0.val.as_words()[0]
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, RngCore, rng};
    use sunscreen_math::{One, Zero};

    use crate::{
        Encoding, GLWE_1_2048_128, GlweDef, PlaintextBits, PolynomialDegree, Random, Torus,
        entities::{GlweCiphertext, GlweSecretKey, Polynomial, RlwePublicKey},
        high_level::encryption::decrypt_glwe,
        math::fgreco::{FGreco, GRECO_MODULUS},
        ops::encryption::{rlwe_encrypt_public, rlwe_generate_public_key},
        polynomial::{polynomial_external_mad, polynomial_mad, polynomial_mad_by_wrap},
        rand::Stddev,
    };

    #[test]
    fn can_mul_fgreco() {
        for _ in 0..100 {
            let a = rand::rng().next_u64() % GRECO_MODULUS;
            let b = rand::rng().next_u64() % GRECO_MODULUS;
            let expected = (a as u128 * b as u128) % GRECO_MODULUS as u128;

            assert_eq!(
                FGreco::from(a) * FGreco::from(b),
                FGreco::from(expected as u64)
            );
        }
    }

    #[test]
    fn can_add_fgreco() {
        for _ in 0..100 {
            let a = rand::rng().next_u64() % GRECO_MODULUS;
            let b = rand::rng().next_u64() % GRECO_MODULUS;
            let expected = (a as u128 + b as u128) % GRECO_MODULUS as u128;

            assert_eq!(
                FGreco::from(a) + FGreco::from(b),
                FGreco::from(expected as u64)
            );
        }
    }

    #[test]
    fn can_encode_fgreco() {
        let x = FGreco::from(0).encode(PlaintextBits(1));

        assert_eq!(x.0.val.as_words()[0], 0);

        let x = FGreco::from(1).encode(PlaintextBits(1));

        assert_eq!(x.0.val.as_words()[0], GRECO_MODULUS / 2);
    }

    #[test]
    fn can_decode_fgreco() {
        let x = FGreco::from(0)
            .encode(PlaintextBits(1))
            .decode(PlaintextBits(1));

        assert_eq!(x.0.val.as_words()[0], 0);

        let x = FGreco::from(1)
            .encode(PlaintextBits(1))
            .decode(PlaintextBits(1));

        assert_eq!(x.0.val.as_words()[0], 1);
    }

    #[test]
    fn can_multiply_polys() {
        let x = Polynomial::new(&vec![
            FGreco::from(1),
            FGreco::from(2),
            FGreco::from(3),
            FGreco::from(4),
        ]);

        let y = x.map(|x| Torus::from(*x));

        let mut c = Polynomial::new(&vec![
            Torus::from(FGreco::from(0)),
            Torus::from(FGreco::from(0)),
            Torus::from(FGreco::from(0)),
            Torus::from(FGreco::from(0)),
        ]);

        polynomial_external_mad(&mut c, &y, &x);

        let expected = Polynomial::new(&vec![
            Torus::from(FGreco::from(0x0018AAC9002C1C67)),
            Torus::from(FGreco::from(0x0018AAC9002C1C6B)),
            Torus::from(FGreco::from(0x0018AAC9002C1C79)),
            Torus::from(FGreco::from(0x0000000000000014)),
        ]);

        assert_eq!(c, expected);
    }

    #[test]
    fn binary_distribution_is_binary() {
        let mut mean = 0.0f64;
        let n = 10_000;

        for _ in 0..n {
            let val = FGreco::binary();

            assert!(val == FGreco::zero() || val == FGreco::one());
            mean += val.to_u64() as f64;
        }

        mean /= n as f64;

        assert!(mean > 0.49 && mean < 0.51);
    }

    #[test]
    fn normal_distribution_is_normal() {
        let mut mean = 0.0f64;
        let n = 10_000;

        for _ in 0..n {
            let val = FGreco::normal(Stddev(1e-15), |x| rng().sample(x));

            let val = val.to_u64();

            if val < GRECO_MODULUS / 2 {
                mean += val as f64;
            } else {
                let val = (GRECO_MODULUS - val) as f64;
                mean -= val;
            }
        }

        mean /= n as f64;

        assert!(mean > -0.5 && mean < 0.5);
    }

    #[test]
    fn can_public_key_encrypt_greco() {
        let mut glwe = GLWE_1_2048_128;
        glwe.dim.polynomial_degree = PolynomialDegree(8);
        let n = glwe.dim.polynomial_degree.0 as u64;

        let sk = GlweSecretKey::<u64>::generate_binary(&glwe);
        let sk_greco = sk.to_greco(&glwe);

        let mut pk = RlwePublicKey::new(&glwe);
        rlwe_generate_public_key(&mut pk, &sk_greco, &glwe);

        let mut ct = GlweCiphertext::new(&glwe);

        let msg = Polynomial::new(
            (0..n)
                .map(|x| {
                    let bit = if x % 2 == 0 {
                        FGreco::zero()
                    } else {
                        FGreco::one()
                    };

                    Torus::encode(bit, PlaintextBits(1))
                })
                .collect::<Vec<_>>()
                .as_slice(),
        );

        rlwe_encrypt_public(&mut ct, &msg, &pk, &glwe);

        let expected = Polynomial::new((0..n).map(|x| x % 2).collect::<Vec<_>>().as_slice());

        let res_ct = ct.to_u64(&glwe);

        let res = decrypt_glwe(&res_ct, &sk, &glwe, PlaintextBits(1));

        assert_eq!(res, expected);
    }
}
