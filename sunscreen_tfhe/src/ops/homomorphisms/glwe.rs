use num::Complex;

use crate::{
    entities::GlweCiphertextFftRef, ops::polynomial::{polynomial_mad_positive_monomial_fft, polynomial_msub_positive_monomial_fft, polynomial_mul_negative_monomial_fft, polynomial_mul_positive_monomial_fft}, polynomial::{
        polynomial_add_assign_fft, polynomial_add_fft, polynomial_sub_assign_fft,
        polynomial_sub_fft,
    }, GlweDef
};

/// Given 2 FFT'd GLEV ciphertexts, compute `a + b`.
pub fn add_glwe_ciphertexts_fft(
    c: &mut GlweCiphertextFftRef<Complex<f64>>,
    a: &GlweCiphertextFftRef<Complex<f64>>,
    b: &GlweCiphertextFftRef<Complex<f64>>,
    glwe: &GlweDef,
) {
    let (c_a, c_b) = c.a_b_mut(glwe);
    let (a_a, a_b) = a.a_b(glwe);
    let (b_a, b_b) = b.a_b(glwe);

    for ((c, a), b) in c_a.zip(a_a).zip(b_a) {
        polynomial_add_fft(c, a, b);
    }

    polynomial_add_fft(c_b, a_b, b_b);
}

/// Given 2 FFT'd GLEV ciphertexts, compute `a - b`.
pub fn sub_glwe_ciphertexts_fft(
    c: &mut GlweCiphertextFftRef<Complex<f64>>,
    a: &GlweCiphertextFftRef<Complex<f64>>,
    b: &GlweCiphertextFftRef<Complex<f64>>,
    glwe: &GlweDef,
) {
    let (c_a, c_b) = c.a_b_mut(glwe);
    let (a_a, a_b) = a.a_b(glwe);
    let (b_a, b_b) = b.a_b(glwe);

    for ((c, a), b) in c_a.zip(a_a).zip(b_a) {
        polynomial_sub_fft(c, a, b);
    }

    polynomial_sub_fft(c_b, a_b, b_b);
}

/// Given 2 FFT'd GLEV ciphertexts, compute `c -= b`.
pub fn sub_assign_glwe_ciphertexts_fft(
    c: &mut GlweCiphertextFftRef<Complex<f64>>,
    b: &GlweCiphertextFftRef<Complex<f64>>,
    glwe: &GlweDef,
) {
    let (c_a, c_b) = c.a_b_mut(glwe);
    let (b_a, b_b) = b.a_b(glwe);

    for (c, b) in c_a.zip(b_a) {
        polynomial_sub_assign_fft(c, b);
    }

    polynomial_sub_assign_fft(c_b, b_b);
}

/// Given 2 FFT'd GLEV ciphertexts, compute `c += b`.
pub fn add_assign_glwe_ciphertexts_fft(
    c: &mut GlweCiphertextFftRef<Complex<f64>>,
    b: &GlweCiphertextFftRef<Complex<f64>>,
    glwe: &GlweDef,
) {
    let (c_a, c_b) = c.a_b_mut(glwe);
    let (b_a, b_b) = b.a_b(glwe);

    for (c, b) in c_a.zip(b_a) {
        polynomial_add_assign_fft(c, b);
    }

    polynomial_add_assign_fft(c_b, b_b);
}

/// Multiply [`GlweCiphertextFft`](crate::entities::GlweCiphertextFft) `a` by `x^i`.
pub fn mul_glwe_ciphertext_positive_monomial_fft(
    c: &mut GlweCiphertextFftRef<Complex<f64>>,
    a: &GlweCiphertextFftRef<Complex<f64>>,
    i: usize,
    glwe: &GlweDef,
) {
    let (c_a, c_b) = c.a_b_mut(glwe);
    let (a_a, a_b) = a.a_b(glwe);

    for (c, a) in c_a.zip(a_a) {
        polynomial_mul_positive_monomial_fft(c, a, i);
    }

    polynomial_mul_positive_monomial_fft(c_b, a_b, i);
}

/// Compute `c += a * x^i`.
pub fn mad_glwe_ciphertext_positive_monomial_fft(
    c: &mut GlweCiphertextFftRef<Complex<f64>>,
    a: &GlweCiphertextFftRef<Complex<f64>>,
    i: usize,
    glwe: &GlweDef,
) {
    let (c_a, c_b) = c.a_b_mut(glwe);
    let (a_a, a_b) = a.a_b(glwe);

    for (c, a) in c_a.zip(a_a) {
        polynomial_mad_positive_monomial_fft(c, a, i);
    }

    polynomial_mad_positive_monomial_fft(c_b, a_b, i);
}

/// Compute `c += a * x^i`.
pub fn msub_glwe_ciphertext_positive_monomial_fft(
    c: &mut GlweCiphertextFftRef<Complex<f64>>,
    a: &GlweCiphertextFftRef<Complex<f64>>,
    i: usize,
    glwe: &GlweDef,
) {
    let (c_a, c_b) = c.a_b_mut(glwe);
    let (a_a, a_b) = a.a_b(glwe);

    for (c, a) in c_a.zip(a_a) {
        polynomial_msub_positive_monomial_fft(c, a, i);
    }

    polynomial_msub_positive_monomial_fft(c_b, a_b, i);
}

/// Multiply [`GlweCiphertextFft`](crate::entities::GlweCiphertextFft) `a` by `x^-i`.
pub fn mul_glwe_ciphertext_negative_monomial_fft(
    c: &mut GlweCiphertextFftRef<Complex<f64>>,
    a: &GlweCiphertextFftRef<Complex<f64>>,
    i: usize,
    glwe: &GlweDef,
) {
    let (c_a, c_b) = c.a_b_mut(glwe);
    let (a_a, a_b) = a.a_b(glwe);

    for (c, a) in c_a.zip(a_a) {
        polynomial_mul_negative_monomial_fft(c, a, i);
    }

    polynomial_mul_negative_monomial_fft(c_b, a_b, i);
}
