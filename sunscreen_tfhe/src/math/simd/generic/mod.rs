use num::{Complex, Float};

use crate::{
    Torus, TorusOps,
    simd::{VectorOps, scalar},
};

impl<S: TorusOps> VectorOps for Torus<S> {
    #[inline(always)]
    fn vector_add(c: &mut [Self], a: &[Self], b: &[Self]) {
        S::vector_add(
            bytemuck::cast_slice_mut(c),
            bytemuck::cast_slice(a),
            bytemuck::cast_slice(b),
        );
    }

    #[inline(always)]
    fn vector_sub(c: &mut [Self], a: &[Self], b: &[Self]) {
        S::vector_sub(
            bytemuck::cast_slice_mut(c),
            bytemuck::cast_slice(a),
            bytemuck::cast_slice(b),
        );
    }

    #[inline(always)]
    fn vector_mod_pow2_q_f64(c: &mut [Self], a: &[f64], log2_q: u64) {
        S::vector_mod_pow2_q_f64(bytemuck::cast_slice_mut(c), bytemuck::cast_slice(a), log2_q);
    }

    fn vector_next_decomp(s: &mut [Self], r: &mut [Self], radix_log: usize) {
        S::vector_next_decomp(
            bytemuck::cast_slice_mut(s),
            bytemuck::cast_slice_mut(r),
            radix_log,
        );
    }
}

impl VectorOps for u64 {
    fn vector_add(c: &mut [Self], a: &[Self], b: &[Self]) {
        scalar::vector_add(c, a, b);
    }

    fn vector_sub(c: &mut [Self], a: &[Self], b: &[Self]) {
        scalar::vector_add(c, a, b);
    }

    fn vector_mod_pow2_q_f64(c: &mut [Self], a: &[f64], log2_q: u64) {
        scalar::vector_mod_pow2_q_f64(c, a, log2_q);
    }

    fn vector_next_decomp(s: &mut [Self], r: &mut [Self], radix_log: usize) {
        scalar::vector_next_decomp(s, r, radix_log);
    }
}

impl VectorOps for u32 {
    #[inline(always)]
    fn vector_add(c: &mut [Self], a: &[Self], b: &[Self]) {
        scalar::vector_add(c, a, b);
    }

    #[inline(always)]
    fn vector_sub(c: &mut [Self], a: &[Self], b: &[Self]) {
        scalar::vector_sub(c, a, b);
    }

    fn vector_mod_pow2_q_f64(c: &mut [Self], a: &[f64], log2_q: u64) {
        scalar::vector_mod_pow2_q_f64(c, a, log2_q);
    }

    fn vector_next_decomp(s: &mut [Self], r: &mut [Self], radix_log: usize) {
        scalar::vector_next_decomp(s, r, radix_log);
    }
}

#[inline]
pub fn complex_twist<T: Float>(c: &mut [Complex<T>], re: &[T], im: &[T], b: &[Complex<T>]) {
    scalar::complex_twist(c, re, im, b)
}

#[inline]
pub fn complex_untwist<T: Float>(output: &mut [T], ifft: &[Complex<T>], twist_inv: &[Complex<T>]) {
    scalar::complex_untwist(output, ifft, twist_inv)
}

/// Compute vector `c += a * b` over &[Complex<f64>].
///
/// # Panics
/// If `c.len() != a.len() != b.len()`
/// If `a.len() % 8 != 0`
/// If `a`, `b`, `c` are not aligned to a 512-bit boundary.
pub fn complex_mad(c: &mut [Complex<f64>], a: &[Complex<f64>], b: &[Complex<f64>]) {
    scalar::complex_mad(c, a, b)
}
