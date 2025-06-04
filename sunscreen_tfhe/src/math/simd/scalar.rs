use std::ops::{Add, Sub};

use num::{Complex, Float};

use crate::FromF64;

pub fn complex_mad(c: &mut [Complex<f64>], a: &[Complex<f64>], b: &[Complex<f64>]) {
    for ((c, a), b) in c.iter_mut().zip(a.iter()).zip(b.iter()) {
        *c += a * b;
    }
}

pub fn complex_twist<T: Float>(c: &mut [Complex<T>], re: &[T], im: &[T], twist: &[Complex<T>]) {
    for ((c, (re, im)), b) in c.iter_mut().zip(re.iter().zip(im.iter())).zip(twist.iter()) {
        *c = Complex::new(*re, *im) * b;
    }
}

pub fn vector_add<T: Sized + Add<T, Output = T> + Clone>(c: &mut [T], a: &[T], b: &[T]) {
    for (c, (a, b)) in c.iter_mut().zip(a.iter().cloned().zip(b.iter().cloned())) {
        *c = a + b;
    }
}

pub fn vector_sub<T: Sized + Sub<T, Output = T> + Clone>(c: &mut [T], a: &[T], b: &[T]) {
    for (c, (a, b)) in c.iter_mut().zip(a.iter().cloned().zip(b.iter().cloned())) {
        *c = a - b;
    }
}

#[inline(always)]
pub fn vector_mod_pow2_q_f64<T: FromF64>(c: &mut [T], a: &[f64], log2_q: u64) {
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

        *o = T::from_f64(ifft);
    }
}

#[cfg(test)]
mod test {
    use rand::{RngCore, thread_rng};

    use super::*;

    #[test]
    fn can_scalar_mad_complex_f64_slice() {
        let a = (0..16)
            .map(|_| {
                Complex::new(
                    thread_rng().next_u64() as f64,
                    thread_rng().next_u64() as f64,
                )
            })
            .collect::<Vec<_>>();

        let b = (0..16)
            .map(|_| {
                Complex::new(
                    thread_rng().next_u64() as f64,
                    thread_rng().next_u64() as f64,
                )
            })
            .collect::<Vec<_>>();

        let mut expected = (0..16)
            .map(|_| {
                Complex::new(
                    thread_rng().next_u64() as f64,
                    thread_rng().next_u64() as f64,
                )
            })
            .collect::<Vec<_>>();

        let mut actual = expected.clone();

        complex_mad(&mut actual, &a, &b);

        for ((c, a), b) in expected.iter_mut().zip(a.iter()).zip(b.iter()) {
            *c += a * b;
        }

        assert_eq!(actual, expected);
    }
}
