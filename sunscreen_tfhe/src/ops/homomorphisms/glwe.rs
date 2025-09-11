use num::Complex;

use crate::{
    GlweDef,
    entities::GlweCiphertextFftRef,
    polynomial::{polynomial_add, polynomial_add_fft, polynomial_sub_fft},
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

/// Given 2 FFT'd GLEV ciphertexts, compute `a + b`.
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
