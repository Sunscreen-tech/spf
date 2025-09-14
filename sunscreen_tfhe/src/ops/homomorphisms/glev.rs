use num::Complex;

use crate::{
    entities::GlevCiphertextFftRef, ops::homomorphisms::{
        add_assign_glwe_ciphertexts_fft, add_glwe_ciphertexts_fft, mad_glwe_ciphertext_positive_monomial_fft, msub_glwe_ciphertext_positive_monomial_fft, mul_glwe_ciphertext_negative_monomial_fft, mul_glwe_ciphertext_positive_monomial_fft, sub_assign_glwe_ciphertexts_fft, sub_glwe_ciphertexts_fft
    }, GlweDef
};

/// Given 2 FFT'd GLEV ciphertexts, compute `a + b`.
pub fn add_glev_ciphertexts_fft(
    c: &mut GlevCiphertextFftRef<Complex<f64>>,
    a: &GlevCiphertextFftRef<Complex<f64>>,
    b: &GlevCiphertextFftRef<Complex<f64>>,
    glwe: &GlweDef,
) {
    for ((c, a), b) in c
        .glwe_ciphertexts_mut(glwe)
        .zip(a.glwe_ciphertexts(glwe))
        .zip(b.glwe_ciphertexts(glwe))
    {
        add_glwe_ciphertexts_fft(c, a, b, glwe);
    }
}

/// Given 2 FFT'd GLEV ciphertexts, compute `a - b`.
pub fn sub_glev_ciphertexts_fft(
    c: &mut GlevCiphertextFftRef<Complex<f64>>,
    a: &GlevCiphertextFftRef<Complex<f64>>,
    b: &GlevCiphertextFftRef<Complex<f64>>,
    glwe: &GlweDef,
) {
    for ((c, a), b) in c
        .glwe_ciphertexts_mut(glwe)
        .zip(a.glwe_ciphertexts(glwe))
        .zip(b.glwe_ciphertexts(glwe))
    {
        sub_glwe_ciphertexts_fft(c, a, b, glwe);
    }
}

/// Given 2 FFT'd GLEV ciphertexts, compute `c -= b`.
pub fn sub_assign_glev_ciphertexts_fft(
    c: &mut GlevCiphertextFftRef<Complex<f64>>,
    b: &GlevCiphertextFftRef<Complex<f64>>,
    glwe: &GlweDef,
) {
    for (c, b) in c.glwe_ciphertexts_mut(glwe).zip(b.glwe_ciphertexts(glwe)) {
        sub_assign_glwe_ciphertexts_fft(c, b, glwe);
    }
}

/// Given 2 FFT'd GLEV ciphertexts, compute `c += b`.
pub fn add_assign_glev_ciphertexts_fft(
    c: &mut GlevCiphertextFftRef<Complex<f64>>,
    b: &GlevCiphertextFftRef<Complex<f64>>,
    glwe: &GlweDef,
) {
    for (c, b) in c.glwe_ciphertexts_mut(glwe).zip(b.glwe_ciphertexts(glwe)) {
        add_assign_glwe_ciphertexts_fft(c, b, glwe);
    }
}

/// Multiply [`GlevCiphertextFft`](crate::entities::GlevCiphertextFft) `a` by `x^i`.
pub fn mul_glev_ciphertext_positive_monomial_fft(
    c: &mut GlevCiphertextFftRef<Complex<f64>>,
    a: &GlevCiphertextFftRef<Complex<f64>>,
    i: usize,
    glwe: &GlweDef,
) {
    for (c, a) in c.glwe_ciphertexts_mut(glwe).zip(a.glwe_ciphertexts(glwe)) {
        mul_glwe_ciphertext_positive_monomial_fft(c, a, i, glwe);
    }
}

/// Compute `c += a * x^i`.
pub fn mad_glev_ciphertext_positive_monomial_fft(
    c: &mut GlevCiphertextFftRef<Complex<f64>>,
    a: &GlevCiphertextFftRef<Complex<f64>>,
    i: usize,
    glwe: &GlweDef,
) {
    for (c, a) in c.glwe_ciphertexts_mut(glwe).zip(a.glwe_ciphertexts(glwe)) {
        mad_glwe_ciphertext_positive_monomial_fft(c, a, i, glwe);
    }
}

/// Compute `c -= a * x^i`.
pub fn msub_glev_ciphertext_positive_monomial_fft(
    c: &mut GlevCiphertextFftRef<Complex<f64>>,
    a: &GlevCiphertextFftRef<Complex<f64>>,
    i: usize,
    glwe: &GlweDef,
) {
    for (c, a) in c.glwe_ciphertexts_mut(glwe).zip(a.glwe_ciphertexts(glwe)) {
        msub_glwe_ciphertext_positive_monomial_fft(c, a, i, glwe);
    }
}

/// Multiply [`GlevCiphertextFft`](crate::entities::GlevCiphertextFft) `a` by `x^-i`.
pub fn mul_glev_ciphertext_negative_monomial_fft(
    c: &mut GlevCiphertextFftRef<Complex<f64>>,
    a: &GlevCiphertextFftRef<Complex<f64>>,
    i: usize,
    glwe: &GlweDef,
) {
    for (c, a) in c.glwe_ciphertexts_mut(glwe).zip(a.glwe_ciphertexts(glwe)) {
        mul_glwe_ciphertext_negative_monomial_fft(c, a, i, glwe);
    }
}
