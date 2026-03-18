use serde::{Deserialize, Serialize};
use sunscreen_math::Zero;

use crate::{
    LweDef, LweDimension, PlaintextBits, Torus, TorusOps,
    dst::{NoWrapper, OverlaySize, dst_from_iter, dst_from_slice},
    macros::{impl_binary_op, impl_unary_op},
    ops::encryption::encode_and_encrypt_lwe_ciphertext,
    rand::{Seed, binary, binary_with_seed, uniform_torus, uniform_torus_with_seed},
};

use super::{LweCiphertext, LweCiphertextRef};

dst! {
    /// An LWE secret key.
    LweSecretKey,
    LweSecretKeyRef,
    NoWrapper,
    (Clone, Debug, Serialize, Deserialize),
    ()
}

impl_binary_op!(Add, LweSecretKey, (TorusOps,));
impl_binary_op!(Sub, LweSecretKey, (TorusOps,));
impl_unary_op!(Neg, LweSecretKey);

impl<S> OverlaySize for LweSecretKeyRef<S>
where
    S: TorusOps,
{
    type Inputs = LweDimension;

    fn size(t: Self::Inputs) -> usize {
        t.0
    }
}

impl<S> LweSecretKey<S>
where
    S: TorusOps,
{
    fn generate(params: &LweDef, torus_element_generator: impl Fn() -> S) -> Self {
        let len = LweSecretKeyRef::<S>::size(params.dim);

        LweSecretKey {
            data: dst_from_slice(
                &(0..len)
                    .map(|_| torus_element_generator())
                    .collect::<Vec<_>>(),
            ),
        }
    }

    /// Construct an LWE secret key from raw coefficients.
    ///
    /// The caller is responsible for ensuring the coefficients represent a valid
    /// secret key for the given parameters. No validation is performed on the
    /// coefficient values (they may be binary, ternary, or uniform).
    ///
    /// # Panics
    ///
    /// Panics if `coefficients.len() != params.dim.0`.
    pub fn from_raw(params: &LweDef, coefficients: &[S]) -> Self {
        let expected_len = LweSecretKeyRef::<S>::size(params.dim);
        assert_eq!(
            coefficients.len(),
            expected_len,
            "coefficient count ({}) does not match LWE dimension ({})",
            coefficients.len(),
            expected_len,
        );
        LweSecretKey {
            data: dst_from_slice(coefficients),
        }
    }

    /// Generate a random binary LWE secret key
    pub fn generate_binary(params: &LweDef) -> Self {
        Self::generate(params, binary)
    }

    /// Generate a secret key with uniformly random coefficients.  This can be
    /// used when performing threshold decryption, which needs random secret
    /// keys that are uniform over the entire ciphertext modulus.  Uniform
    /// secret keys are also valid keys for encryption/decryption but are not
    /// widely used.
    pub fn generate_uniform(params: &LweDef) -> Self {
        Self::generate(params, || uniform_torus::<S>().inner())
    }

    /// Generate a binary LWE secret key with a specific seed for deterministic generation.
    ///
    /// # Security
    /// The key generation is deterministic based on the seed, which means that
    /// the seed should be considered secret as well and kept secure.
    pub fn generate_binary_with_seed(params: &LweDef, seed: &Seed) -> Self {
        LweSecretKey::generate_binary_with_rng(params, &mut seed.create_rng())
    }

    /// Generate a uniform LWE secret key with a specific seed for deterministic generation.
    pub fn generate_uniform_with_seed(params: &LweDef, seed: &Seed) -> Self {
        let len = LweSecretKeyRef::<S>::size(params.dim);
        let mut rng = seed.create_rng();

        LweSecretKey {
            data: dst_from_iter((0..len).map(|_| uniform_torus_with_seed::<S>(&mut rng).inner())),
        }
    }

    /// Generate a binary LWE secret key using a provided mutable RNG.
    pub(crate) fn generate_binary_with_rng(
        params: &LweDef,
        rng: &mut crate::rand::SeededRng,
    ) -> Self {
        let len = LweSecretKeyRef::<S>::size(params.dim);

        LweSecretKey {
            data: dst_from_iter((0..len).map(|_| binary_with_seed::<S>(rng))),
        }
    }
}

impl<S> LweSecretKeyRef<S>
where
    S: TorusOps,
{
    /// Create an LWE ciphertext from a given message with a private key. The
    /// message should be in the plaintext space, and will be encoded onto the
    /// Torus automatically.
    pub fn encrypt(
        &self,
        msg: S,
        params: &LweDef,
        plaintext_bits: PlaintextBits,
    ) -> (LweCiphertext<S>, Torus<S>) {
        params.assert_valid();
        assert!(plaintext_bits.0 < S::BITS);

        let mut ct = LweCiphertext::<S>::zero(params);

        let e = encode_and_encrypt_lwe_ciphertext(&mut ct, self, msg, params, plaintext_bits);

        (ct, e)
    }

    /// Decrypts the given ciphertext, returning the message. The message will
    /// not be decoded into the plaintext space; the caller is responsible for
    /// performing operations like shifting by delta and rounding. See
    /// [Self::decrypt] for a function that performs the decoding automatically.
    pub fn decrypt_without_decode(&self, ct: &LweCiphertextRef<S>, params: &LweDef) -> Torus<S> {
        params.assert_valid();
        ct.assert_is_valid(params.dim);

        let (a, b) = ct.a_b(params);

        let mut dot = Torus::<S>::zero();

        for (a_i, d_i) in a.iter().zip(self.data.iter()) {
            dot += a_i * d_i
        }

        b - dot
    }

    /// Decrypts and decodes a ciphertext, returning the message. The message
    /// will be decoded into the plaintext space. See
    /// [Self::decrypt_without_decode] for a function that does not perform the
    /// decoding.
    pub fn decrypt(
        &self,
        ct: &LweCiphertextRef<S>,
        params: &LweDef,
        plaintext_bits: PlaintextBits,
    ) -> S {
        params.assert_valid();
        assert!(plaintext_bits.0 < S::BITS);
        ct.assert_is_valid(params.dim);

        let msg = self.decrypt_without_decode(ct, params);

        msg.decode(plaintext_bits)
    }
}

impl<S> LweSecretKeyRef<S>
where
    S: TorusOps,
{
    /// Returns the secret key data as a slice.
    pub fn s(&self) -> &[S] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use crate::high_level::*;
    use num::traits::{WrappingAdd, WrappingNeg, WrappingSub};

    // Addition

    #[test]
    fn add_secret_keys() {
        let params = &TEST_LWE_DEF_1;

        let sk = keygen::generate_uniform_lwe_sk(params);
        let sk2 = keygen::generate_uniform_lwe_sk(params);

        let sk3_expected = sk
            .s()
            .iter()
            .zip(sk2.s().iter())
            .map(|(a, b)| a.wrapping_add(b))
            .collect::<Vec<_>>();

        let sk3 = sk + sk2;

        assert_eq!(sk3_expected, sk3.s())
    }

    #[test]
    fn add_assign_secret_keys() {
        let params = &TEST_LWE_DEF_1;

        let sk = keygen::generate_uniform_lwe_sk(params);
        let mut sk2 = keygen::generate_uniform_lwe_sk(params);

        let sk2_expected = sk
            .s()
            .iter()
            .zip(sk2.s().iter())
            .map(|(a, b)| a.wrapping_add(b))
            .collect::<Vec<_>>();

        sk2 += sk;

        assert_eq!(sk2_expected, sk2.s())
    }

    #[test]
    fn add_secret_key_refs() {
        let params = &TEST_LWE_DEF_1;

        let sk = keygen::generate_uniform_lwe_sk(params);
        let sk2 = keygen::generate_uniform_lwe_sk(params);

        let sk3_expected = sk
            .s()
            .iter()
            .zip(sk2.s().iter())
            .map(|(a, b)| a.wrapping_add(b))
            .collect::<Vec<_>>();

        let sk3 = sk.as_ref() + sk2.as_ref();

        assert_eq!(sk3_expected, sk3.s())
    }

    #[test]
    fn wrapping_add_secret_keys() {
        let params = &TEST_LWE_DEF_1;

        let sk = keygen::generate_uniform_lwe_sk(params);
        let sk2 = keygen::generate_uniform_lwe_sk(params);

        let sk3_expected = sk
            .s()
            .iter()
            .zip(sk2.s().iter())
            .map(|(a, b)| a.wrapping_add(b))
            .collect::<Vec<_>>();

        let sk3 = sk.wrapping_add(&sk2);

        assert_eq!(sk3_expected, sk3.s())
    }

    // Subtraction

    #[test]
    fn sub_secret_keys() {
        let params = &TEST_LWE_DEF_1;

        let sk = keygen::generate_uniform_lwe_sk(params);
        let sk2 = keygen::generate_uniform_lwe_sk(params);

        let sk3_expected = sk
            .s()
            .iter()
            .zip(sk2.s().iter())
            .map(|(a, b)| a.wrapping_sub(b))
            .collect::<Vec<_>>();

        let sk3 = sk - sk2;

        assert_eq!(sk3_expected, sk3.s())
    }

    #[test]
    fn sub_assign_secret_keys() {
        let params = &TEST_LWE_DEF_1;

        let sk = keygen::generate_uniform_lwe_sk(params);
        let mut sk2 = keygen::generate_uniform_lwe_sk(params);

        let sk2_expected = sk2
            .s()
            .iter()
            .zip(sk.s().iter())
            .map(|(a, b)| a.wrapping_sub(b))
            .collect::<Vec<_>>();

        sk2 -= sk;

        assert_eq!(sk2_expected, sk2.s())
    }

    #[test]
    fn sub_secret_key_refs() {
        let params = &TEST_LWE_DEF_1;

        let sk = keygen::generate_uniform_lwe_sk(params);
        let sk2 = keygen::generate_uniform_lwe_sk(params);

        let sk3_expected = sk
            .s()
            .iter()
            .zip(sk2.s().iter())
            .map(|(a, b)| a.wrapping_sub(b))
            .collect::<Vec<_>>();

        let sk3 = sk.as_ref() - sk2.as_ref();

        assert_eq!(sk3_expected, sk3.s())
    }

    #[test]
    fn wrapping_sub_secret_keys() {
        let params = &TEST_LWE_DEF_1;

        let sk = keygen::generate_uniform_lwe_sk(params);
        let sk2 = keygen::generate_uniform_lwe_sk(params);

        let sk3_expected = sk
            .s()
            .iter()
            .zip(sk2.s().iter())
            .map(|(a, b)| a.wrapping_sub(b))
            .collect::<Vec<_>>();

        let sk3 = sk.wrapping_sub(&sk2);

        assert_eq!(sk3_expected, sk3.s())
    }

    // Negation

    #[test]
    fn neg_secret_key() {
        let params = &TEST_LWE_DEF_1;

        let sk = keygen::generate_uniform_lwe_sk(params);

        let sk2_expected = sk.s().iter().map(|a| a.wrapping_neg()).collect::<Vec<_>>();
        let sk2 = -sk;

        assert_eq!(sk2_expected, sk2.s())
    }

    #[test]
    fn neg_secret_key_ref() {
        let params = &TEST_LWE_DEF_1;

        let sk = keygen::generate_uniform_lwe_sk(params);

        let sk2_expected = sk.s().iter().map(|a| a.wrapping_neg()).collect::<Vec<_>>();
        let sk2 = -sk.as_ref();

        assert_eq!(sk2_expected, sk2.s())
    }

    #[test]
    fn wrapping_neg_secret_key() {
        let params = &TEST_LWE_DEF_1;

        let sk = keygen::generate_uniform_lwe_sk(params);

        let sk2_expected = sk.s().iter().map(|a| a.wrapping_neg()).collect::<Vec<_>>();
        let sk2 = sk.wrapping_neg();

        assert_eq!(sk2_expected, sk2.s())
    }

    // from_raw tests

    #[test]
    fn from_raw_binary_key() {
        use super::LweSecretKey;

        let params = &TEST_LWE_DEF_1;
        let coefficients: Vec<u64> = (0..params.dim.0).map(|i| (i % 2) as u64).collect();

        let sk = LweSecretKey::<u64>::from_raw(params, &coefficients);
        assert_eq!(sk.s(), &coefficients);
    }

    #[test]
    fn from_raw_ternary_key() {
        use super::LweSecretKey;

        let params = &TEST_LWE_DEF_1;
        let coefficients: Vec<u64> = (0..params.dim.0)
            .map(|i| match i % 3 {
                0 => 0u64,
                1 => 1u64,
                _ => u64::MAX, // -1 mod 2^64
            })
            .collect();

        let sk = LweSecretKey::<u64>::from_raw(params, &coefficients);
        assert_eq!(sk.s(), &coefficients);
    }

    #[test]
    fn from_raw_round_trip() {
        use super::LweSecretKey;
        use crate::PlaintextBits;

        let params = &TEST_LWE_DEF_1;
        let bits = PlaintextBits(4);

        let original_sk = keygen::generate_binary_lwe_sk(params);
        let coefficients: Vec<u64> = original_sk.s().to_vec();

        let reconstructed_sk = LweSecretKey::<u64>::from_raw(params, &coefficients);

        let msg = 7u64;
        let (ct, _) = original_sk.encrypt(msg, params, bits);
        let decrypted = reconstructed_sk.decrypt(&ct, params, bits);

        assert_eq!(decrypted, msg);
    }

    #[test]
    #[should_panic(expected = "does not match")]
    fn from_raw_panics_on_wrong_dimension() {
        use super::LweSecretKey;

        let params = &TEST_LWE_DEF_1;
        let wrong_len = params.dim.0 + 1;
        let coefficients: Vec<u64> = vec![0u64; wrong_len];
        LweSecretKey::<u64>::from_raw(params, &coefficients);
    }
}
