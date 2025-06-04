use std::arch::x86_64::{
    __m256i, _mm256_add_epi64, _mm256_load_si256, _mm256_store_si256, _mm256_sub_epi64,
};

use num::Complex;

use crate::FromF64;

#[inline]
#[target_feature(enable = "avx2,fma")]
pub fn complex_mad_avx2(c: &mut [Complex<f64>], a: &[Complex<f64>], b: &[Complex<f64>]) {
    for ((c, a), b) in c.iter_mut().zip(a.iter()).zip(b.iter()) {
        *c += a * b;
    }
}

#[inline]
#[target_feature(enable = "avx2")]
pub fn vector_add_u64(c: &mut [u64], a: &[u64], b: &[u64]) {
    let len = c.len() / 4;

    for i in 0..len {
        unsafe {
            let a_vals = _mm256_load_si256(a.as_ptr().add(i * 4) as *const __m256i);
            let b_vals = _mm256_load_si256(b.as_ptr().add(i * 4) as *const __m256i);
            let c_vals = _mm256_add_epi64(a_vals, b_vals);
            _mm256_store_si256(c.as_mut_ptr().add(i * 4) as *mut __m256i, c_vals);
        }
    }
}

#[inline]
#[target_feature(enable = "avx2")]
pub fn vector_sub_u64(c: &mut [u64], a: &[u64], b: &[u64]) {
    let len = c.len() / 4;

    for i in 0..len {
        unsafe {
            let a_vals = _mm256_load_si256(a.as_ptr().add(i * 4) as *const __m256i);
            let b_vals = _mm256_load_si256(b.as_ptr().add(i * 4) as *const __m256i);
            let c_vals = _mm256_sub_epi64(a_vals, b_vals);
            _mm256_store_si256(c.as_mut_ptr().add(i * 4) as *mut __m256i, c_vals);
        }
    }
}

#[target_feature(enable = "avx2,fma")]
#[inline]
pub fn vector_mod_pow2_q_f64_u64(c: &mut [u64], a: &[f64], log2_q: u64) {
    // When the exponent != 0 && exponent != 1024,
    // IEEE-754 doubles are represented as -1**s * 1.m * 2**(e - 1023).
    //
    // m is 52 bits, e is 11 bits, and s is 1 bit.
    //
    // Thus, to compute 2**x, we set e = 1023 + x, m=0, and s = 0. So, we just
    // need to fill in EXP and shift it up 52 places.
    //
    // We first reduce modulo q
    let exp: u64 = 1023 + log2_q;
    let q: f64 = f64::from_bits(exp << 52);

    let exp_div_2 = exp - 1;
    let q_div_2 = f64::from_bits(exp_div_2 << 52);

    // Exploit the fact that q is a power of 2 when performing the modulo
    // reduction. Could possibly be even faster by masking and shifting
    // the mantissa and tweaking the exponent. However, profiling on ARM
    // indicates this is no longer a bottleneck with the code below.
    //
    // See https://stackoverflow.com/questions/49139283/are-there-any-numbers-that-enable-fast-modulo-calculation-on-floats
    //
    // Don't know why Rust decides not to inline this. Inlining allows
    // the below loop to get unrolled, vectorized, and division gets
    // replaced with multiplication since q is a known constant.
    #[inline(always)]
    fn mod_q(val: f64, q: f64) -> f64 {
        f64::mul_add(-(val / q).trunc(), q, val)
    }

    for (o, ifft) in c.iter_mut().zip(a.iter()) {
        let mut ifft = mod_q(*ifft, q);

        // Next, we need to adjust x outside [-q/2, q/2) to wrap to the correct torus
        // point.
        if ifft >= q_div_2 {
            ifft -= q;
        } else if ifft <= -q_div_2 {
            ifft += q;
        }

        *o = u64::from_f64(ifft);
    }
}

#[cfg(test)]
mod tests {
    use crate::{math::simd::VectorOps, simd::x86_64::avx2_available};

    #[test]
    fn can_vector_add_u64() {
        if avx2_available() {
            let a = avec_from_iter!(0..64u64);
            let b = avec_from_iter!(0..64u64);
            let mut c = avec_from_iter!((0..64).map(|_| 0u64));
            let expected = avec_from_iter!(a.iter().zip(b.iter()).map(|(a, b)| a + b));

            u64::vector_add(&mut c, &a, &b);

            assert_eq!(expected, c);
        }
    }

    #[test]
    fn can_vector_sub_u64() {
        if avx2_available() {
            let a = avec_from_iter!((0..64u64).map(|x| 4 * x));
            let b = avec_from_iter!(0..64u64);
            let mut c = avec_from_iter!((0..64).map(|_| 0u64));
            let expected = avec_from_iter!(a.iter().zip(b.iter()).map(|(a, b)| a - b));

            u64::vector_sub(&mut c, &a, &b);

            assert_eq!(expected, c);
        }
    }
}
