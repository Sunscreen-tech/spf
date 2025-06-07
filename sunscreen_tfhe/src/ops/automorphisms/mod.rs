use num::Complex;

use crate::{
    GlweDef, OverlaySize, RadixDecomposition, TorusOps,
    dst::FromMutSlice,
    entities::{AutmorphismKeyFftRef, AutmorphismKeyRef, GlweCiphertextRef, GlweSecretKeyRef},
    ops::{
        ciphertext::glwe_add_assign, fft_ops::keyswitch_glwe_to_glwe,
        keyswitch::glwe_keyswitch_key::generate_keyswitch_key_glwe, polynomial::polynomial_pow_k,
    },
    scratch::allocate_scratch_ref,
};

/// Generate a new [`AutomorphismKey`](crate::entities::automorphism_key::AutomorphismKey) set for the given `glwe_sk`.
///
/// # Panics
/// If the given entities are invalid for the given parameters.
pub fn generate_automorphism_key<S: TorusOps>(
    ak: &mut AutmorphismKeyRef<S>,
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

/// Compute the homomorphic trace on a given [`GlweCiphertext`]. This zeros all
/// coefficients except the constant term, which is multiplied by N.
///
/// # Panics
/// If the given parameters are invalid.
/// If the given entities are invalid for the given parameters.
pub fn trace<S: TorusOps>(
    out: &mut GlweCiphertextRef<S>,
    x: &GlweCiphertextRef<S>,
    ak: &AutmorphismKeyFftRef<Complex<f64>>,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
) {
    glwe.assert_valid();
    radix.assert_valid::<S>();
    out.assert_is_valid(glwe.dim);
    x.assert_is_valid(glwe.dim);
    ak.assert_is_valid((glwe.dim, radix.count));

    allocate_scratch_ref!(keyswitched, GlweCiphertextRef<S>, (glwe.dim));
    allocate_scratch_ref!(glwe_k, GlweCiphertextRef<S>, (glwe.dim));
    let poly_degree = glwe.dim.polynomial_degree.0;

    out.clone_from_ref(x);

    for (i, glwe_ksk) in (1..=poly_degree.ilog2()).zip(ak.keyswitch_keys(glwe, radix)) {
        let k = poly_degree / (1 << (i - 1)) + 1;

        for (glwe_k_a, x_a) in glwe_k.a_mut(glwe).zip(out.a(glwe)) {
            polynomial_pow_k::<_, S>(glwe_k_a, x_a, k);
        }

        polynomial_pow_k::<_, S>(glwe_k.b_mut(glwe), out.b(glwe), k);

        keyswitch_glwe_to_glwe(keyswitched, glwe_k, glwe_ksk, glwe, radix);

        glwe_add_assign(out, &keyswitched, glwe);
    }
}

#[cfg(test)]
mod tests {
    use num::Complex;

    use crate::{
        GLWE_1_2048_128, RadixCount, RadixDecomposition, RadixLog,
        entities::{
            AutomorphismKey, AutomorphismKeyFft, GlweCiphertext, GlweSecretKey, Polynomial,
        },
        high_level::encryption::decrypt_glwe,
        ops::automorphisms::{generate_automorphism_key, trace},
    };

    #[test]
    fn can_trace() {
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

        let ct = glwe_sk.encode_encrypt_glwe(&poly, &glwe, crate::PlaintextBits(12));

        let mut out = GlweCiphertext::new(&glwe);

        trace(&mut out, &ct, &ak_fft, &glwe, &radix);

        let actual = decrypt_glwe(&out, &glwe_sk, &glwe, crate::PlaintextBits(12));

        // The constant coefficient should be multiplied by N
        assert_eq!(actual.coeffs()[0], glwe.dim.polynomial_degree.0 as u64);

        // Everywhere else should be zero
        for i in actual.coeffs().iter().skip(1) {
            assert_eq!(*i, 0);
        }
    }
}
