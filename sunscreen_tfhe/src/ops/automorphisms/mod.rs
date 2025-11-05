use num::Complex;

use crate::{
    GlweDef, OverlaySize, RadixDecomposition, TorusOps,
    dst::FromMutSlice,
    entities::{AutomorphismKeyFftRef, AutomorphismKeyRef, GlweCiphertextRef, GlweSecretKeyRef},
    ops::{
        ciphertext::{add_glwe_ciphertexts, glwe_add_assign, glwe_mod_switch_and_expand_pow_2},
        fft_ops::keyswitch_glwe_to_glwe,
        keyswitch::glwe_keyswitch_key::generate_keyswitch_key_glwe,
        polynomial::polynomial_pow_k,
    },
    scratch::allocate_scratch_ref,
};

/// Generate a new [`AutomorphismKey`](crate::entities::AutomorphismKey) set for the given `glwe_sk`.
///
/// The automorphism key is a set of keyswitching keys. In this particular
/// implementation, the set is defined by
///
/// d = [2^{log(N)} + 1, ..., 2^{log(N) - i + 1} + 1, ..., 2^1 + 1]
/// for i = [1, ..., log(N)]
///
/// Note that the key is defined in the aformentioned order.
///
/// # Panics
/// If the given entities are invalid for the given parameters.
pub fn generate_automorphism_key<S: TorusOps>(
    ak: &mut AutomorphismKeyRef<S>,
    glwe_sk: &GlweSecretKeyRef<S>,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
) {
    glwe.assert_valid();
    radix.assert_valid::<S>();
    ak.assert_is_valid((glwe.dim, radix.count));
    glwe_sk.assert_is_valid(glwe.dim);

    let poly_degree = glwe.dim.polynomial_degree.0;

    allocate_scratch_ref!(glwe_sk_k, GlweSecretKeyRef<S>, (glwe.dim));

    // For each k=2^i + 1, compute a new glwe secret key where each polynomial is mapped
    // X |-> X^k. Then generate a GLWE keyswitch key to that secret key.
    for (i, glwe_ksk) in (1..=poly_degree.ilog2()).zip(ak.keyswitch_keys_mut(glwe, radix)) {
        let k = poly_degree / (1 << (i - 1)) + 1;

        for (glwe_sk_k, glwe_sk) in glwe_sk_k.s_mut(glwe).zip(glwe_sk.s(glwe)) {
            polynomial_pow_k(glwe_sk_k, glwe_sk, k);
        }

        generate_keyswitch_key_glwe(glwe_ksk, glwe_sk_k, glwe_sk, glwe, radix)
    }
}

fn eval_auto<S: TorusOps>(
    out: &mut GlweCiphertextRef<S>,
    x: &GlweCiphertextRef<S>,
    d: usize,
    ak: &AutomorphismKeyFftRef<Complex<f64>>,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
) {
    allocate_scratch_ref!(glwe_k, GlweCiphertextRef<S>, (glwe.dim));

    let atk_d = ak.keyswitch_key_at(d, glwe, radix);

    for (glwe_k_a, x_a) in glwe_k.a_mut(glwe).zip(x.a(glwe)) {
        polynomial_pow_k::<_, S>(glwe_k_a, x_a, d);
    }

    polynomial_pow_k::<_, S>(glwe_k.b_mut(glwe), x.b(glwe), d);

    keyswitch_glwe_to_glwe(out, glwe_k, atk_d, glwe, radix);
}

/// Compute the homomorphic trace on a given [`GlweCiphertext`](crate::entities::GlweCiphertext). This zeros all
/// coefficients except the constant term, which is multiplied by N
/// (i.e. the GLWE polynomial degree).
///
/// In the LY25 paper, this is called "HomTrace(C, n)", where n = 1.
///
/// # Panics
/// If the given parameters are invalid.
/// If the given entities are invalid for the given parameters.
pub fn trace<S: TorusOps>(
    out: &mut GlweCiphertextRef<S>,
    x: &GlweCiphertextRef<S>,
    ak: &AutomorphismKeyFftRef<Complex<f64>>,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
) {
    glwe.assert_valid();
    radix.assert_valid::<S>();
    out.assert_is_valid(glwe.dim);
    x.assert_is_valid(glwe.dim);
    ak.assert_is_valid((glwe.dim, radix.count));

    allocate_scratch_ref!(eval_auto_term, GlweCiphertextRef<S>, (glwe.dim));

    let poly_degree = glwe.dim.polynomial_degree.0;

    out.clone_from_ref(x);

    for k in 1..=poly_degree.ilog2() {
        // 2^{log(N) - k + 1}
        let d = poly_degree / (1 << (k - 1)) + 1;
        eval_auto(eval_auto_term, out, d, ak, glwe, radix);
        glwe_add_assign(out, eval_auto_term, glwe);
    }
}

/// Compute the homomorphic trace on a given [`GlweCiphertext`](crate::entities::GlweCiphertext). This zeros all
/// coefficients except the constant term, which is multiplied by N
/// (i.e. the GLWE polynomial degree).
///
/// In the LY25 paper, this is called "RevHomTrace(C, n)", where n = 1.
///
/// # Panics
/// If the given parameters are invalid.
/// If the given entities are invalid for the given parameters.
pub fn rev_trace<S: TorusOps>(
    out: &mut GlweCiphertextRef<S>,
    x: &GlweCiphertextRef<S>,
    ak: &AutomorphismKeyFftRef<Complex<f64>>,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
) {
    glwe.assert_valid();
    radix.assert_valid::<S>();
    out.assert_is_valid(glwe.dim);
    x.assert_is_valid(glwe.dim);
    ak.assert_is_valid((glwe.dim, radix.count));

    let poly_degree = glwe.dim.polynomial_degree.0;

    out.clone_from_ref(x);

    allocate_scratch_ref!(eval_auto_term, GlweCiphertextRef<S>, (glwe.dim));
    allocate_scratch_ref!(mod_switch_term, GlweCiphertextRef<S>, (glwe.dim));

    for k in 1..=poly_degree.ilog2() {
        // 2^k + 1
        let d = (1 << k) + 1;

        // Switch from q to q/2 and back
        glwe_mod_switch_and_expand_pow_2(mod_switch_term, out, glwe, 1);
        eval_auto(eval_auto_term, mod_switch_term, d, ak, glwe, radix);

        add_glwe_ciphertexts(out, mod_switch_term, eval_auto_term, glwe);
    }
}

#[cfg(test)]
mod tests {
    use num::Complex;
    use rand::Rng;

    use crate::{
        GLWE_1_2048_128, PlaintextBits, RadixCount, RadixDecomposition, RadixLog,
        entities::{
            AutomorphismKey, AutomorphismKeyFft, GlweCiphertext, GlweSecretKey, Polynomial,
        },
        high_level::encryption::decrypt_glwe,
        ops::automorphisms::{generate_automorphism_key, rev_trace, trace},
    };

    #[test]
    fn can_trace() {
        let plaintext_bits = PlaintextBits(12);
        let glwe = GLWE_1_2048_128;
        let radix = RadixDecomposition {
            count: RadixCount(6),
            radix_log: RadixLog(7),
        };

        let glwe_sk = GlweSecretKey::<u64>::generate_binary(&glwe);

        let mut ak = AutomorphismKey::<u64>::new(&glwe, &radix);
        generate_automorphism_key(&mut ak, &glwe_sk, &glwe, &radix);
        let mut ak_fft = AutomorphismKeyFft::<Complex<f64>>::new(&glwe, &radix);
        ak.fft(&mut ak_fft, &glwe, &radix);

        let poly = Polynomial::new(
            &(0..glwe.dim.polynomial_degree.0)
                .map(|_| 1u64)
                .collect::<Vec<_>>(),
        );

        let ct = glwe_sk.encode_encrypt_glwe(&poly, &glwe, plaintext_bits);

        let mut out = GlweCiphertext::new(&glwe);

        trace(&mut out, &ct, &ak_fft, &glwe, &radix);

        let actual = decrypt_glwe(&out, &glwe_sk, &glwe, plaintext_bits);

        // The constant coefficient should be multiplied by N
        assert_eq!(actual.coeffs()[0], glwe.dim.polynomial_degree.0 as u64);

        // Everywhere else should be zero
        for i in actual.coeffs().iter().skip(1) {
            assert_eq!(*i, 0);
        }
    }

    #[test]
    fn can_rev_trace() {
        let plaintext_bits = PlaintextBits(12);

        let glwe = GLWE_1_2048_128;
        let radix = RadixDecomposition {
            count: RadixCount(6),
            radix_log: RadixLog(7),
        };

        let glwe_sk = GlweSecretKey::<u64>::generate_binary(&glwe);

        let mut ak = AutomorphismKey::<u64>::new(&glwe, &radix);
        generate_automorphism_key(&mut ak, &glwe_sk, &glwe, &radix);
        let mut ak_fft = AutomorphismKeyFft::<Complex<f64>>::new(&glwe, &radix);
        ak.fft(&mut ak_fft, &glwe, &radix);

        let mut rng = rand::rng();

        for _ in 0..10 {
            let constant_coeff = rng.random_range(0..8);

            let poly = Polynomial::new(
                &(0..glwe.dim.polynomial_degree.0)
                    .map(|i| if i == 0 { constant_coeff } else { 1u64 })
                    .collect::<Vec<_>>(),
            );

            let ct = glwe_sk.encode_encrypt_glwe(&poly, &glwe, plaintext_bits);

            let mut out = GlweCiphertext::new(&glwe);

            rev_trace(&mut out, &ct, &ak_fft, &glwe, &radix);

            let actual = decrypt_glwe(&out, &glwe_sk, &glwe, plaintext_bits);

            // The constant coefficient should remain unchanged (no factor of N)
            assert_eq!(actual.coeffs()[0], constant_coeff);

            // Everywhere else should be zero
            for i in actual.coeffs().iter().skip(1) {
                assert_eq!(*i, 0);
            }
        }
    }
}
