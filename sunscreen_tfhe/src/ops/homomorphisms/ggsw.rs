use num::Complex;

use crate::{
    GlweDef, RadixDecomposition,
    entities::GgswCiphertextFftRef,
    ops::homomorphisms::{
        add_glev_ciphertexts_fft, mul_glev_ciphertext_negative_monomial_fft,
        mul_glev_ciphertext_positive_monomial_fft, sub_glev_ciphertexts_fft,
    },
};

/// Given 2 FFT'd GGSW ciphertexts, compute `a + b`.
pub fn add_ggsw_ciphertexts_fft(
    c: &mut GgswCiphertextFftRef<Complex<f64>>,
    a: &GgswCiphertextFftRef<Complex<f64>>,
    b: &GgswCiphertextFftRef<Complex<f64>>,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
) {
    for ((c, a), b) in c
        .rows_mut(glwe, radix)
        .zip(a.rows(glwe, radix))
        .zip(b.rows(glwe, radix))
    {
        add_glev_ciphertexts_fft(c, a, b, glwe);
    }
}

/// Given 2 FFT'd GGSW ciphertexts, compute `a + b`.
pub fn sub_ggsw_ciphertexts_fft(
    c: &mut GgswCiphertextFftRef<Complex<f64>>,
    a: &GgswCiphertextFftRef<Complex<f64>>,
    b: &GgswCiphertextFftRef<Complex<f64>>,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
) {
    for ((c, a), b) in c
        .rows_mut(glwe, radix)
        .zip(a.rows(glwe, radix))
        .zip(b.rows(glwe, radix))
    {
        sub_glev_ciphertexts_fft(c, a, b, glwe);
    }
}

/// Multiply [`GgswCiphertextFft`](crate::entities::GgswCiphertextFft) `a` by `x^i`.
pub fn mul_ggsw_ciphertext_positive_monomial_fft(
    c: &mut GgswCiphertextFftRef<Complex<f64>>,
    a: &GgswCiphertextFftRef<Complex<f64>>,
    i: usize,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
) {
    for (c, a) in c.rows_mut(glwe, radix).zip(a.rows(glwe, radix)) {
        mul_glev_ciphertext_positive_monomial_fft(c, a, i, glwe);
    }
}

/// Multiply [`GgswCiphertextFft`](crate::entities::GgswCiphertextFft) `a` by `x^-i`.
pub fn mul_ggsw_ciphertext_negative_monomial_fft(
    c: &mut GgswCiphertextFftRef<Complex<f64>>,
    a: &GgswCiphertextFftRef<Complex<f64>>,
    i: usize,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
) {
    for (c, a) in c.rows_mut(glwe, radix).zip(a.rows(glwe, radix)) {
        mul_glev_ciphertext_negative_monomial_fft(c, a, i, glwe);
    }
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, rng};

    use super::*;

    use crate::{
        GLWE_1_2048_128, PlaintextBits, RadixCount, RadixDecomposition, RadixLog,
        entities::{GgswCiphertextFft, GlweSecretKey, Polynomial},
        high_level::{self, encryption::decrypt_ggsw},
    };

    #[test]
    fn can_add_ggsws() {
        let glwe = GLWE_1_2048_128;
        let radix = RadixDecomposition {
            radix_log: RadixLog(8),
            count: RadixCount(2),
        };
        let sk = GlweSecretKey::generate_binary(&glwe);

        for _ in 0..10 {
            let a_msg = rng().next_u64() % 2;
            let b_msg = rng().next_u64() % 2;

            let a =
                high_level::encryption::encrypt_ggsw(a_msg, &sk, &glwe, &radix, PlaintextBits(1));
            let a = high_level::fft::fft_ggsw(&a, &glwe, &radix);

            let b =
                high_level::encryption::encrypt_ggsw(b_msg, &sk, &glwe, &radix, PlaintextBits(1));
            let b = high_level::fft::fft_ggsw(&b, &glwe, &radix);

            let mut c = GgswCiphertextFft::new(&glwe, &radix);

            add_ggsw_ciphertexts_fft(&mut c, &a, &b, &glwe, &radix);

            let c = high_level::fft::ifft_ggsw(&c, &glwe, &radix);

            let actual = decrypt_ggsw(&c, &sk, &glwe, &radix, PlaintextBits(1));

            assert_eq!(actual.coeffs()[0], a_msg + b_msg);
        }
    }

    #[test]
    fn can_sub_ggsws() {
        let glwe = GLWE_1_2048_128;
        let radix = RadixDecomposition {
            radix_log: RadixLog(8),
            count: RadixCount(2),
        };
        let sk = GlweSecretKey::generate_binary(&glwe);

        for _ in 0..10 {
            let a_msg = rng().next_u64() % 2;
            let b_msg = rng().next_u64() % 2;

            let a =
                high_level::encryption::encrypt_ggsw(a_msg, &sk, &glwe, &radix, PlaintextBits(1));
            let a = high_level::fft::fft_ggsw(&a, &glwe, &radix);

            let b =
                high_level::encryption::encrypt_ggsw(b_msg, &sk, &glwe, &radix, PlaintextBits(1));
            let b = high_level::fft::fft_ggsw(&b, &glwe, &radix);

            let mut c = GgswCiphertextFft::new(&glwe, &radix);

            sub_ggsw_ciphertexts_fft(&mut c, &a, &b, &glwe, &radix);

            let c = high_level::fft::ifft_ggsw(&c, &glwe, &radix);

            let actual = decrypt_ggsw(&c, &sk, &glwe, &radix, PlaintextBits(1));

            assert_eq!(
                actual.coeffs()[0],
                a_msg.wrapping_sub(b_msg) % (0x1 << radix.radix_log.0) as u64
            );
        }
    }

    #[test]
    fn can_mul_ggsw_fft_by_positive_monomial_negacyclic() {
        let glwe = GLWE_1_2048_128;
        let radix = RadixDecomposition {
            radix_log: RadixLog(8),
            count: RadixCount(2),
        };

        let sk = GlweSecretKey::generate_binary(&glwe);

        let msg = Polynomial::new(
            &(0..2048u64)
                .map(|_| rng().next_u64() % 2)
                .collect::<Vec<_>>(),
        );

        let ct = sk.encode_encrypt_ggsw(&msg, &glwe, &radix, PlaintextBits(1));

        let ct_fft = high_level::fft::fft_ggsw(&ct, &glwe, &radix);

        for i in 0..4096 {
            let mut actual_fft = GgswCiphertextFft::new(&glwe, &radix);

            mul_ggsw_ciphertext_positive_monomial_fft(&mut actual_fft, &ct_fft, i, &glwe, &radix);

            let actual = high_level::fft::ifft_ggsw(&actual_fft, &glwe, &radix);
            let actual = decrypt_ggsw(&actual, &sk, &glwe, &radix, PlaintextBits(1));

            let mut expected = msg.as_torus().to_owned();
            expected.mul_by_positive_monomial_negacyclic(i);
            let expected = expected.map(|x| x.inner() % (0x1 << radix.radix_log.0));

            assert_eq!(actual.coeffs(), expected.coeffs())
        }
    }

    #[test]
    fn can_mul_ggsw_fft_by_negative_monomial_negacyclic() {
        let glwe = GLWE_1_2048_128;
        let radix = RadixDecomposition {
            radix_log: RadixLog(8),
            count: RadixCount(2),
        };

        let sk = GlweSecretKey::generate_binary(&glwe);

        let msg = Polynomial::new(
            &(0..2048u64)
                .map(|_| rng().next_u64() % 2)
                .collect::<Vec<_>>(),
        );

        let ct = sk.encode_encrypt_ggsw(&msg, &glwe, &radix, PlaintextBits(1));

        let ct_fft = high_level::fft::fft_ggsw(&ct, &glwe, &radix);

        for i in 0..4096 {
            let mut actual_fft = GgswCiphertextFft::new(&glwe, &radix);

            mul_ggsw_ciphertext_negative_monomial_fft(&mut actual_fft, &ct_fft, i, &glwe, &radix);

            let actual = high_level::fft::ifft_ggsw(&actual_fft, &glwe, &radix);
            let actual = decrypt_ggsw(&actual, &sk, &glwe, &radix, PlaintextBits(1));

            let mut expected = msg.as_torus().to_owned();
            expected.mul_by_negative_monomial_negacyclic(i);
            let expected = expected.map(|x| x.inner() % (0x1 << radix.radix_log.0));

            assert_eq!(actual.coeffs(), expected.coeffs())
        }
    }
}
