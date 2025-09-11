use num::Complex;

use crate::{
    GlweDef, RadixDecomposition,
    entities::GlevCiphertextFftRef,
    ops::{
        ciphertext::add_glwe_ciphertexts,
        homomorphisms::{add_glwe_ciphertexts_fft, sub_glwe_ciphertexts_fft},
    },
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

/// Given 2 FFT'd GLEV ciphertexts, compute `a + b`.
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
