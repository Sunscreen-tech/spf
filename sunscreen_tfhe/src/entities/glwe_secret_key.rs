use serde::{Deserialize, Serialize};

use crate::{
    GlweDef, GlweDimension, PlaintextBits, RadixDecomposition, Torus, TorusOps,
    dst::{FromSlice, NoWrapper, OverlaySize},
    entities::GgswCiphertext,
    macros::{impl_binary_op, impl_unary_op},
    ops::encryption::{
        decrypt_glwe_ciphertext, encrypt_ggsw_ciphertext, encrypt_glwe_ciphertext_secret,
    },
    rand::{Seed, binary, binary_with_seed, uniform_torus, uniform_torus_with_seed},
};

use super::{
    GlweCiphertext, GlweCiphertextRef, LweSecretKeyRef, ParallelPolynomialIterator, Polynomial,
    PolynomialIterator, PolynomialIteratorMut, PolynomialRef,
};

dst! {
    /// A GLWE secret key. This is a list of `s` polynomials of degree `n` where
    /// `n` is the polynomial degree. The length of the list is `k` where `k` is
    /// the size of the GLWE secret key.
    GlweSecretKey,
    GlweSecretKeyRef,
    NoWrapper,
    (Clone, Debug, Serialize, Deserialize),
    (TorusOps,)
}

// We can use these macros (which does operations on the underlying data vector)
// because addition, subtraction, and negation of polynomials is just element
// wise addition, subtraction, and negation of the underlying data vector.
impl_binary_op!(Add, GlweSecretKey, (TorusOps,));
impl_binary_op!(Sub, GlweSecretKey, (TorusOps,));
impl_unary_op!(Neg, GlweSecretKey);

impl<S> OverlaySize for GlweSecretKeyRef<S>
where
    S: TorusOps,
{
    type Inputs = GlweDimension;

    fn size(t: Self::Inputs) -> usize {
        PolynomialRef::<S>::size(t.polynomial_degree) * t.size.0
    }
}

impl<S> GlweSecretKey<S>
where
    S: TorusOps,
{
    fn generate(params: &GlweDef, torus_element_generator: impl Fn() -> S) -> GlweSecretKey<S> {
        params.assert_valid();

        let len = GlweSecretKeyRef::<S>::size(params.dim);

        GlweSecretKey {
            data: avec_from_iter!((0..len).map(|_| torus_element_generator())),
        }
    }

    /// Generate a random binary GLWE secret key.
    pub fn generate_binary(params: &GlweDef) -> GlweSecretKey<S> {
        Self::generate(params, binary)
    }

    /// Generate a secret key with uniformly random coefficients.  This can be
    /// used when performing threshold decryption, which needs random secret
    /// keys that are uniform over the entire ciphertext modulus.  Uniform
    /// secret keys are also valid keys for encryption/decryption but are not
    /// widely used.
    pub fn generate_uniform(params: &GlweDef) -> GlweSecretKey<S> {
        Self::generate(params, || uniform_torus::<S>().inner())
    }

    /// Generate a binary GLWE secret key with a specific seed for deterministic generation.
    pub fn generate_binary_with_seed(params: &GlweDef, seed: &Seed) -> GlweSecretKey<S> {
        GlweSecretKey::generate_binary_with_rng(params, &mut seed.create_rng())
    }

    /// Generate a uniform GLWE secret key with a specific seed for deterministic generation.
    pub fn generate_uniform_with_seed(params: &GlweDef, seed: &Seed) -> GlweSecretKey<S> {
        params.assert_valid();

        let len = GlweSecretKeyRef::<S>::size(params.dim);
        let mut rng = seed.create_rng();

        GlweSecretKey {
            data: avec_from_iter!((0..len).map(|_| uniform_torus_with_seed::<S>(&mut rng).inner())),
        }
    }

    /// Generate a binary GLWE secret key using a provided mutable RNG.
    pub fn generate_binary_with_rng(
        params: &GlweDef,
        rng: &mut crate::rand::SeededRng,
    ) -> GlweSecretKey<S> {
        params.assert_valid();

        let len = GlweSecretKeyRef::<S>::size(params.dim);

        GlweSecretKey {
            data: avec_from_iter!((0..len).map(|_| binary_with_seed::<S>(rng))),
        }
    }
}

impl<S> GlweSecretKeyRef<S>
where
    S: TorusOps,
{
    /// Returns an iterator over the `s` polynomials in a GLWE secret key.
    pub fn s(&self, params: &GlweDef) -> PolynomialIterator<'_, S> {
        PolynomialIterator::new(&self.data, params.dim.polynomial_degree.0)
    }

    /// Returns a parallel iterator over the `s` polynomials in a GLWE secret key.
    pub fn s_par(&self, params: &GlweDef) -> ParallelPolynomialIterator<'_, S> {
        ParallelPolynomialIterator::new(&self.data, params.dim.polynomial_degree.0)
    }

    /// Decrypts and decodes a GLWE ciphertext into a polynomial.
    pub fn decrypt_decode_glwe(
        &self,
        ct: &GlweCiphertextRef<S>,
        params: &GlweDef,
        plaintext_bits: PlaintextBits,
    ) -> Polynomial<S>
    where
        S: TorusOps,
    {
        params.assert_valid();
        assert!(plaintext_bits.0 < S::BITS);
        ct.assert_is_valid(params.dim);

        let mut result = Polynomial::zero(ct.a_b(params).1.len());

        decrypt_glwe_ciphertext(&mut result, ct, self, params);

        result.map(|x| x.decode(plaintext_bits))
    }

    /// Encodes and encrypts a message as a GLWE ciphertext using a secret key.
    pub fn encode_encrypt_glwe(
        &self,
        plaintext: &PolynomialRef<S>,
        params: &GlweDef,
        plaintext_bits: PlaintextBits,
    ) -> GlweCiphertext<S>
    where
        S: TorusOps,
    {
        let plaintext = plaintext.map(|x| Torus::encode(*x, plaintext_bits));

        let mut ct = GlweCiphertext::new(params);

        encrypt_glwe_ciphertext_secret(&mut ct, &plaintext, self, params);

        ct
    }

    /// Encodes and encrypts a message as a GGSW ciphertext using a secret key.
    pub fn encode_encrypt_ggsw(
        &self,
        msg: &PolynomialRef<S>,
        params: &GlweDef,
        radix: &RadixDecomposition,
        plaintext_bits: PlaintextBits,
    ) -> GgswCiphertext<S>
    where
        S: TorusOps,
    {
        let mut ggsw = GgswCiphertext::new(params, radix);

        encrypt_ggsw_ciphertext(&mut ggsw, msg, self, params, radix, plaintext_bits);

        ggsw
    }

    /// Returns a representation of a GLWE secret key as an LWE secret key.
    /// This is a LWE secret key with dimension `N * k` where `N` is the
    /// polynomial degree and `k` is the size of the GLWE secret key.
    ///
    /// # Remarks
    /// This is useful when decrypting or keyswitching values after calling
    /// [`sample_extract`](crate::ops::ciphertext::sample_extract).
    pub fn to_lwe_secret_key(&self) -> &LweSecretKeyRef<S> {
        LweSecretKeyRef::from_slice(&self.data)
    }
}

impl<S> GlweSecretKeyRef<S>
where
    S: TorusOps,
{
    /// Returns an mutable iterator over the `s` polynomials in a GLWE secret
    /// key.
    pub fn s_mut(&mut self, params: &GlweDef) -> PolynomialIteratorMut<'_, S> {
        PolynomialIteratorMut::new(&mut self.data, params.dim.polynomial_degree.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::{GLWE_1_2048_128, high_level::*, rand::Seed};

    use num::traits::{WrappingAdd, WrappingNeg, WrappingSub};

    #[test]
    fn secret_key_dimensions() {
        let params = GLWE_1_2048_128;

        let sk = keygen::generate_binary_glwe_sk(&params);

        assert_eq!(sk.s(&params).count(), params.dim.size.0);

        for s_i in sk.s(&params) {
            assert_eq!(s_i.len(), params.dim.polynomial_degree.0);

            for s in s_i.coeffs() {
                assert!(*s == 0 || *s == 1);
            }
        }
    }

    // Addition

    #[test]
    fn add_secret_keys() {
        let params = GLWE_1_2048_128;

        let sk = keygen::generate_uniform_glwe_sk(&params);
        let sk2 = keygen::generate_uniform_glwe_sk(&params);

        let sk3_expected = avec_from_iter!(
            sk.data
                .iter()
                .zip(sk2.data.iter())
                .map(|(a, b)| a.wrapping_add(b))
        );

        let sk3 = sk + sk2;

        assert_eq!(sk3_expected, sk3.data)
    }

    #[test]
    fn add_assign_secret_keys() {
        let params = GLWE_1_2048_128;

        let sk = keygen::generate_uniform_glwe_sk(&params);
        let mut sk2 = keygen::generate_uniform_glwe_sk(&params);

        let sk2_expected = avec_from_iter!(
            sk.data
                .iter()
                .zip(sk2.data.iter())
                .map(|(a, b)| a.wrapping_add(b))
        );

        sk2 += sk;

        assert_eq!(sk2_expected, sk2.data)
    }

    #[test]
    fn add_secret_key_refs() {
        let params = GLWE_1_2048_128;

        let sk = keygen::generate_uniform_glwe_sk(&params);
        let sk2 = keygen::generate_uniform_glwe_sk(&params);

        let sk3_expected = avec_from_iter!(
            sk.data
                .iter()
                .zip(sk2.data.iter())
                .map(|(a, b)| a.wrapping_add(b))
        );

        let sk3 = sk.as_ref() + sk2.as_ref();

        assert_eq!(sk3_expected, sk3.data)
    }

    #[test]
    fn wrapping_add_secret_keys() {
        let params = GLWE_1_2048_128;

        let sk = keygen::generate_uniform_glwe_sk(&params);
        let sk2 = keygen::generate_uniform_glwe_sk(&params);

        let sk3_expected = avec_from_iter!(
            sk.data
                .iter()
                .zip(sk2.data.iter())
                .map(|(a, b)| a.wrapping_add(b))
        );

        let sk3 = sk.wrapping_add(&sk2);

        assert_eq!(sk3_expected, sk3.data)
    }

    // Subtraction

    #[test]
    fn sub_secret_keys() {
        let params = GLWE_1_2048_128;

        let sk = keygen::generate_uniform_glwe_sk(&params);
        let sk2 = keygen::generate_uniform_glwe_sk(&params);

        let sk3_expected = avec_from_iter!(
            sk.data
                .iter()
                .zip(sk2.data.iter())
                .map(|(a, b)| a.wrapping_sub(b))
        );

        let sk3 = sk - sk2;

        assert_eq!(sk3_expected, sk3.data)
    }

    #[test]
    fn sub_assign_secret_keys() {
        let params = GLWE_1_2048_128;

        let sk = keygen::generate_uniform_glwe_sk(&params);
        let mut sk2 = keygen::generate_uniform_glwe_sk(&params);

        let sk2_expected = avec_from_iter!(
            sk2.data
                .iter()
                .zip(sk.data.iter())
                .map(|(a, b)| a.wrapping_sub(b))
        );

        sk2 -= sk;

        assert_eq!(sk2_expected, sk2.data)
    }

    #[test]
    fn sub_secret_key_refs() {
        let params = GLWE_1_2048_128;

        let sk = keygen::generate_uniform_glwe_sk(&params);
        let sk2 = keygen::generate_uniform_glwe_sk(&params);

        let sk3_expected = avec_from_iter!(
            sk.data
                .iter()
                .zip(sk2.data.iter())
                .map(|(a, b)| a.wrapping_sub(b))
        );

        let sk3 = sk.as_ref() - sk2.as_ref();

        assert_eq!(sk3_expected, sk3.data)
    }

    #[test]
    fn wrapping_sub_secret_keys() {
        let params = GLWE_1_2048_128;

        let sk = keygen::generate_uniform_glwe_sk(&params);
        let sk2 = keygen::generate_uniform_glwe_sk(&params);

        let sk3_expected = avec_from_iter!(
            sk.data
                .iter()
                .zip(sk2.data.iter())
                .map(|(a, b)| a.wrapping_sub(b))
        );

        let sk3 = sk.wrapping_sub(&sk2);

        assert_eq!(sk3_expected, sk3.data)
    }

    // Negation

    #[test]
    fn neg_secret_key() {
        let params = GLWE_1_2048_128;

        let sk = keygen::generate_uniform_glwe_sk(&params);

        let sk2_expected = avec_from_iter!(sk.data.iter().map(|a| a.wrapping_neg()));
        let sk2 = -sk;

        assert_eq!(sk2_expected, sk2.data)
    }

    #[test]
    fn neg_secret_key_ref() {
        let params = GLWE_1_2048_128;

        let sk = keygen::generate_uniform_glwe_sk(&params);

        let sk2_expected = avec_from_iter!(sk.data.iter().map(|a| a.wrapping_neg()));
        let sk2 = -sk.as_ref();

        assert_eq!(sk2_expected, sk2.data)
    }

    #[test]
    fn wrapping_neg_secret_key() {
        let params = GLWE_1_2048_128;

        let sk = keygen::generate_binary_glwe_sk(&params);

        let sk2_expected = avec_from_iter!(sk.data.iter().map(|a| a.wrapping_neg()));
        let sk2 = sk.wrapping_neg();

        assert_eq!(sk2_expected, sk2.data)
    }

    #[test]
    fn seeded_binary_glwe_deterministic() {
        let params = GLWE_1_2048_128;
        let seed = Seed::from_bytes([42u8; 32]);

        let sk1 = keygen::generate_binary_glwe_sk_with_seed(&params, &seed);
        let sk2 = keygen::generate_binary_glwe_sk_with_seed(&params, &seed);

        // Keys should be identical
        assert_eq!(sk1.data, sk2.data);

        // Values should be binary
        for s_poly in sk1.s(&params) {
            for coeff in s_poly.coeffs() {
                assert!(*coeff == 0 || *coeff == 1);
            }
        }
    }

    #[test]
    fn seeded_uniform_glwe_deterministic() {
        let params = GLWE_1_2048_128;
        let seed = Seed::from_bytes([123u8; 32]);

        let sk1 = keygen::generate_uniform_glwe_sk_with_seed(&params, &seed);
        let sk2 = keygen::generate_uniform_glwe_sk_with_seed(&params, &seed);

        // Keys should be identical
        assert_eq!(sk1.data, sk2.data);
    }

    #[test]
    fn seeded_glwe_different_seeds() {
        let params = GLWE_1_2048_128;
        let seed1 = Seed::from_bytes([1u8; 32]);
        let seed2 = Seed::from_bytes([2u8; 32]);

        let sk1 = keygen::generate_binary_glwe_sk_with_seed(&params, &seed1);
        let sk2 = keygen::generate_binary_glwe_sk_with_seed(&params, &seed2);

        // Keys should be different
        assert_ne!(sk1.data, sk2.data);
    }
}
