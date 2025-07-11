mod avx2;
mod avx512;

use std::{arch::x86_64::__m512d, sync::OnceLock};

use num::{Complex, Float};
use raw_cpuid::CpuId;

use crate::{
    Torus, TorusOps,
    simd::{VectorOps, scalar},
};

#[inline(always)]
fn avx_512_available() -> bool {
    static AVX512_AVAILABLE: OnceLock<bool> = OnceLock::new();

    *AVX512_AVAILABLE.get_or_init(|| {
        if let Some(e) = CpuId::new().get_extended_feature_info() {
            e.has_avx512f()
        } else {
            false
        }
    })
}

#[inline(always)]
fn avx2_available() -> bool {
    static AVX2_AVAILABLE: OnceLock<bool> = OnceLock::new();

    *AVX2_AVAILABLE.get_or_init(|| {
        if let Some(e) = CpuId::new().get_extended_feature_info() {
            e.has_avx2()
        } else {
            false
        }
    })
}

#[inline(always)]
fn fma_available() -> bool {
    static FMA_AVAILABLE: OnceLock<bool> = OnceLock::new();

    *FMA_AVAILABLE.get_or_init(|| {
        if let Some(e) = CpuId::new().get_feature_info() {
            e.has_fma()
        } else {
            false
        }
    })
}

/// Compute vector `c += a * b` over &[Complex<f64>].
///
/// # Panics
/// If `c.len() != a.len() != b.len()`
/// If `a.len() % 8 != 0`
/// If `a`, `b`, `c` are not aligned to a 512-bit boundary.
pub fn complex_mad(c: &mut [Complex<f64>], a: &[Complex<f64>], b: &[Complex<f64>]) {
    // Regardless of our runtime vectorization strategy, our input buffers should be aligned for AVX512.
    assert_eq!(c.as_ptr().align_offset(core::mem::align_of::<__m512d>()), 0);
    assert_eq!(b.as_ptr().align_offset(core::mem::align_of::<__m512d>()), 0);
    assert_eq!(a.as_ptr().align_offset(core::mem::align_of::<__m512d>()), 0);
    assert_eq!(c.len(), a.len());
    assert_eq!(b.len(), a.len());
    assert_eq!(a.len() % 8, 0);

    if avx_512_available() {
        unsafe { avx512::complex_mad_avx_512_unchecked(c, a, b) }
    } else if fma_available() && avx2_available() {
        unsafe { avx2::complex_mad_avx2(c, a, b) }
    } else {
        scalar::complex_mad(c, a, b)
    }
}

#[inline]
pub fn complex_twist<T: Float>(c: &mut [Complex<T>], re: &[T], im: &[T], b: &[Complex<T>]) {
    if fma_available() && avx2_available() {
        unsafe { avx2::complex_twist(c, re, im, b) }
    } else {
        scalar::complex_twist(c, re, im, b)
    }
}

#[inline]
pub fn complex_untwist<T: Float>(output: &mut [T], ifft: &[Complex<T>], twist_inv: &[Complex<T>]) {
    if fma_available() && avx2_available() {
        unsafe { avx2::complex_untwist(output, ifft, twist_inv) }
    } else {
        scalar::complex_untwist(output, ifft, twist_inv)
    }
}

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

    fn vector_scalar_mad(c: &mut [Self], a: &[Self], s: Self) {
        S::vector_scalar_mad(
            bytemuck::cast_slice_mut(c),
            bytemuck::cast_slice(a),
            s.inner(),
        );
    }

    fn vector_shr_round(c: &mut [Self], a: &[Self], n: u32) {
        S::vector_shr_round(bytemuck::cast_slice_mut(c), bytemuck::cast_slice(a), n);
    }
}

impl VectorOps for u64 {
    fn vector_add(c: &mut [Self], a: &[Self], b: &[Self]) {
        if fma_available() && avx2_available() {
            unsafe { avx2::vector_add_u64(c, a, b) };
        } else {
            scalar::vector_add(c, a, b);
        }
    }

    fn vector_sub(c: &mut [Self], a: &[Self], b: &[Self]) {
        if avx2_available() {
            unsafe { avx2::vector_sub_u64(c, a, b) };
        } else {
            scalar::vector_add(c, a, b);
        }
    }

    #[inline(always)]
    fn vector_mod_pow2_q_f64(c: &mut [Self], a: &[f64], log2_q: u64) {
        if avx2_available() {
            unsafe { avx2::vector_mod_pow2_q_f64_u64(c, a, log2_q) }
        } else {
            scalar::vector_mod_pow2_q_f64(c, a, log2_q);
        }
    }

    #[inline(always)]
    fn vector_next_decomp(s: &mut [Self], r: &mut [Self], radix_log: usize) {
        if avx2_available() && fma_available() {
            unsafe { avx2::vector_next_decomp(s, r, radix_log) };
        } else {
            scalar::vector_next_decomp(s, r, radix_log);
        }
    }

    #[inline(always)]
    fn vector_scalar_mad(c: &mut [Self], a: &[Self], s: Self) {
        if avx_512_available() {
            avx512::vector_scalar_mad(c, a, s);
        } else {
            scalar::vector_scalar_mad(c, a, s);
        }
    }

    #[inline(always)]
    fn vector_shr_round(c: &mut [Self], a: &[Self], n: u32) {
        if avx2_available() && fma_available() {
            unsafe { avx2::vector_shr_round(c, a, n) };
        } else {
            scalar::vector_shr_round(c, a, n);
        }
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

    #[inline(always)]
    fn vector_scalar_mad(c: &mut [Self], a: &[Self], s: Self) {
        scalar::vector_scalar_mad(c, a, s);
    }

    #[inline(always)]
    fn vector_shr_round(c: &mut [Self], a: &[Self], n: u32) {
        scalar::vector_shr_round(c, a, n);
    }
}

#[cfg(test)]
mod tests {
    use aligned_vec::AVec;

    use super::*;

    #[test]
    fn can_scalar_mad_complex_f64_slice() {
        let len = 1024;

        let vals_0 = (0..len).map(|x| x as f64).collect::<Vec<_>>();
        let vals_1 = (len..2 * len).map(|x| x as f64).collect::<Vec<_>>();
        let vals_2 = (2 * len..3 * len).map(|x| x as f64).collect::<Vec<_>>();

        let a =
            AVec::<Complex<f64>>::from_iter(64, vals_0.chunks(2).map(|x| Complex::new(x[0], x[1])));
        let b =
            AVec::<Complex<f64>>::from_iter(64, vals_1.chunks(2).map(|x| Complex::new(x[0], x[1])));
        let mut expected =
            AVec::<Complex<f64>>::from_iter(64, vals_2.chunks(2).map(|x| Complex::new(x[0], x[1])));

        let mut actual = expected.clone();

        complex_mad(&mut actual, &a, &b);
        scalar::complex_mad(&mut expected, &a, &b);

        assert_eq!(expected, actual);
    }
}
