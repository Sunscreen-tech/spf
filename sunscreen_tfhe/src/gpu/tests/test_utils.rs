#![allow(unused)]

use num::Complex;
use rand::{Rng, RngCore, rng};

use crate::{
    GlweDef, PlaintextBits, PolynomialDegree, RadixDecomposition, Torus,
    entities::{
        DstArrayRef, GgswCiphertextRef, GlevCiphertextRef, GlweCiphertextRef, GlweSecretKey,
        Polynomial, PolynomialFftRef, PolynomialRef,
    },
    ops::encryption::{
        encrypt_ggsw_ciphertext, encrypt_ggsw_ciphertext_scalar, encrypt_glwe_ciphertext_secret,
        encrypt_secret_glev_ciphertext,
    },
};

pub(crate) fn glwe_encrypt<F>(
    cts: &mut DstArrayRef<GlweCiphertextRef<u64>>,
    msg_gen: F,
    sk: &GlweSecretKey<u64>,
    glwe: &GlweDef,
) where
    F: Fn(usize, PolynomialDegree) -> Polynomial<Torus<u64>>,
{
    for (i, ct) in cts.iter_mut(glwe.dim).enumerate() {
        let pt = msg_gen(i, glwe.dim.polynomial_degree);

        encrypt_glwe_ciphertext_secret(ct, &pt, &sk, &glwe);
    }
}

pub(crate) fn glev_encrypt<F>(
    cts: &mut DstArrayRef<GlevCiphertextRef<u64>>,
    msg_gen: F,
    sk: &GlweSecretKey<u64>,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
) where
    F: Fn(usize, PolynomialDegree) -> Polynomial<Torus<u64>>,
{
    for (i, ct) in cts.iter_mut((glwe.dim, radix.count)).enumerate() {
        let pt = msg_gen(i, glwe.dim.polynomial_degree);

        encrypt_secret_glev_ciphertext(ct, &pt, sk, glwe, radix);
    }
}

pub(crate) fn ggsw_encrypt(
    cts: &mut DstArrayRef<GgswCiphertextRef<u64>>,
    sk: &GlweSecretKey<u64>,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
) {
    for (i, ct) in cts.iter_mut((glwe.dim, radix.count)).enumerate() {
        encrypt_ggsw_ciphertext_scalar(ct, rng().next_u64() % 2, sk, glwe, radix, PlaintextBits(1));
    }
}

pub(crate) fn random_poly_mod(
    polys: &mut DstArrayRef<PolynomialRef<u64>>,
    degree: &PolynomialDegree,
    modulus: u64,
) {
    for poly in polys.iter_mut(*degree) {
        for c in poly.coeffs_mut().iter_mut() {
            *c = rng().next_u64() % modulus;
        }
    }
}

pub(crate) fn random_poly_mod_2_pow_64(
    polys: &mut DstArrayRef<PolynomialRef<u64>>,
    degree: &PolynomialDegree,
) {
    for poly in polys.iter_mut(*degree) {
        for c in poly.coeffs_mut().iter_mut() {
            *c = rng().next_u64();
        }
    }
}

/// Creates a polynomial of random Torus T[X] for T in [0, q).
pub(crate) fn random_torus_poly(
    polys: &mut DstArrayRef<PolynomialRef<Torus<u64>>>,
    degree: &PolynomialDegree,
) {
    for poly in polys.iter_mut(*degree) {
        for c in poly.coeffs_mut().iter_mut() {
            *c = Torus::from(rng().next_u64());
        }
    }
}

pub(crate) fn random_complex_poly_mod(
    polys: &mut DstArrayRef<PolynomialRef<Complex<f64>>>,
    degree: &PolynomialDegree,
    modulus: f64,
) {
    for poly in polys.iter_mut(*degree) {
        for (i, c) in poly.coeffs_mut().iter_mut().enumerate() {
            c.re = 2.0 * modulus * (rng().random::<f64>() - 0.5);
            c.im = 2.0 * modulus * (rng().random::<f64>() - 0.5);
        }
    }
}

pub(crate) fn random_complex_polyfft_mod(
    polys: &mut DstArrayRef<PolynomialFftRef<Complex<f64>>>,
    degree: &PolynomialDegree,
    modulus: f64,
) {
    for poly in polys.iter_mut(*degree) {
        for (i, c) in poly.coeffs_mut().iter_mut().enumerate() {
            c.re = 2.0 * modulus * (rng().random::<f64>() - 0.5);
            c.im = 2.0 * modulus * (rng().random::<f64>() - 0.5);
        }
    }
}

pub(crate) fn one_poly(polys: &mut DstArrayRef<PolynomialRef<u64>>, degree: &PolynomialDegree) {
    for poly in polys.iter_mut(*degree) {
        for (i, c) in poly.coeffs_mut().iter_mut().enumerate() {
            *c = if i == 0 { 1 } else { 0 };
        }
    }
}

pub(crate) fn constant_poly(
    polys: &mut DstArrayRef<PolynomialRef<u64>>,
    degree: &PolynomialDegree,
    val: u64,
) {
    for poly in polys.iter_mut(*degree) {
        for (i, c) in poly.coeffs_mut().iter_mut().enumerate() {
            *c = val;
        }
    }
}

pub(crate) fn random_msg(_i: usize, degree: PolynomialDegree) -> Polynomial<Torus<u64>> {
    Polynomial::new(
        &(0..degree.0)
            .map(|_| Torus::encode(rng().next_u64() % 2, PlaintextBits(1)))
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn zero_msg(_i: usize, degree: PolynomialDegree) -> Polynomial<Torus<u64>> {
    Polynomial::zero(degree.0)
}

pub(crate) fn one_msg(_i: usize, degree: PolynomialDegree) -> Polynomial<Torus<u64>> {
    let mut msg = Polynomial::<Torus<u64>>::zero(degree.0);
    msg.coeffs_mut()[0] = Torus::encode(1, PlaintextBits(1));

    msg
}

pub(crate) fn monotonic_msg(i: usize, degree: PolynomialDegree) -> Polynomial<Torus<u64>> {
    Polynomial::new(
        &(0..degree.0)
            .map(|x| Torus::encode((i * degree.0 + x) as u64, PlaintextBits(1)))
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn fill_complex_rand_mod(data: &mut [Complex<f64>], modulus: f64) {
    for c in data.iter_mut() {
        c.re = 2.0 * modulus * (rng().random::<f64>() - 0.5);
        c.im = 2.0 * modulus * (rng().random::<f64>() - 0.5);
    }
}
