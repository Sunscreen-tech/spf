use std::{
    fmt::{Binary, LowerHex, UpperHex},
    ops::{Add, BitAnd, BitAndAssign, BitOr, BitOrAssign, Mul, Not, Shl, Shr, Sub},
};

use bytemuck::{Pod, Zeroable};
use num::{
    Bounded, Num,
    traits::{WrappingAdd, WrappingMul, WrappingNeg, WrappingShl, WrappingShr, WrappingSub},
};
use sunscreen_math::{
    BarrettConfig, One, Zero, refify_binary_op,
    ring::{BarrettBackend, Zq},
};

use crate::{
    FromF64, FromU64, NumBits, ReinterpretAsSigned, ToF64, ToU64, TorusOps, simd::VectorOps,
};

const P: u64 = 6943179709095039;

#[derive(BarrettConfig)]
#[barrett_config(modulus = "6943179709095039", num_limbs = 1)]
struct BarrettConfig;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
struct FGreco(Zq<1, BarrettBackend<1, BarrettConfig>>);

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
        Self(Zq::from(P) - Zq::one())
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

impl TorusOps for FGreco {}

impl NumBits for FGreco {
    /// This is a hack. Don't use any code paths that need this.
    const BITS: u32 = 0;
}

impl From<u64> for FGreco {
    fn from(value: u64) -> Self {
        Self(Zq::from(value))
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use crate::math::fgreco::{FGreco, P};

    #[test]
    fn can_mul_fgreco() {
        for _ in 0..100 {
            let a = rand::rng().next_u64() % P;
            let b = rand::rng().next_u64() % P;
            let expected = (a as u128 * b as u128) % P as u128;

            assert_eq!(
                FGreco::from(a) * FGreco::from(b),
                FGreco::from(expected as u64)
            );
        }
    }

    #[test]
    fn can_add_fgreco() {
        for _ in 0..100 {
            let a = rand::rng().next_u64() % P;
            let b = rand::rng().next_u64() % P;
            let expected = (a as u128 + b as u128) % P as u128;

            assert_eq!(
                FGreco::from(a) + FGreco::from(b),
                FGreco::from(expected as u64)
            );
        }
    }
}
