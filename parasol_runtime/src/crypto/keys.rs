use num::Complex;
use serde::{Deserialize, Serialize};
use std::mem::size_of;
use sunscreen_tfhe::OverlaySize;
use sunscreen_tfhe::entities::{
    AutomorphismKey, AutomorphismKeyFft, AutomorphismKeyFftRef, AutomorphismKeyRef, BootstrapKey,
    BootstrapKeyFft, BootstrapKeyRef, GlweSecretKey, GlweSecretKeyRef, LweKeyswitchKey,
    LweKeyswitchKeyRef, LweSecretKey, LweSecretKeyRef, RlwePublicKey, RlwePublicKeyRef,
    SchemeSwitchKey, SchemeSwitchKeyFft, SchemeSwitchKeyRef,
};
pub use sunscreen_tfhe::high_level::keygen::Seed;
use sunscreen_tfhe::high_level::{fft, keygen};
use sunscreen_tfhe::ops::automorphisms::generate_automorphism_key;
use sunscreen_tfhe::ops::bootstrapping::generate_scheme_switch_key;
use sunscreen_tfhe::ops::encryption::rlwe_generate_public_key;

use crate::DEFAULT_128;
use crate::params::Params;
use crate::safe_bincode::GetSize;

#[derive(Clone, Serialize, Deserialize)]
/// A public key
///
/// # Remarks
/// FHE public keys are 10s of kB and you should generally serialize them using APIs that
/// provide compact arrays, such as [`bincode`]. JSON is not recommended.
pub struct PublicKey {
    /// The inner [`RlwePublicKey`]
    pub rlwe_1: RlwePublicKey<u64>,
}

impl GetSize for PublicKey {
    fn get_size(params: &Params) -> usize {
        // Magic 1 is the length in the serialized sequence.
        (RlwePublicKeyRef::<u64>::size(params.l1_params.dim) + 1) * size_of::<u64>()
    }

    fn check_is_valid(&self, params: &Params) -> crate::Result<()> {
        Ok(self.rlwe_1.check_is_valid(params.l1_params.dim)?)
    }
}

impl PublicKey {
    /// Generate a public key from the given secret key.
    ///
    /// # Panics
    /// If the passed parameters aren't the same as those used when generating the secret key.
    ///
    /// Additionally, the params must feature a level-1 GLWE polynomial count of 1. I.e.
    /// `params.l1_params.dim.count.0 == 1`. [`crate::DEFAULT_128`] have this property.
    ///
    /// # Examples
    /// ```
    /// use parasol_runtime::{DEFAULT_128, PublicKey, SecretKey};
    ///
    /// let sk = SecretKey::generate(&DEFAULT_128);
    /// let pk = PublicKey::generate(&DEFAULT_128, &sk);
    /// ```
    pub fn generate(params: &Params, sk: &SecretKey) -> Self {
        assert_eq!(
            params.l1_params.dim.size.0, 1,
            "Unfortunately, public keys currently require a GLWE size of 1. This restriction will likely be eased in the future."
        );

        let mut pk = RlwePublicKey::new(&params.l1_params);

        rlwe_generate_public_key(&mut pk, &sk.glwe_1, &params.l1_params);

        Self { rlwe_1: pk }
    }

    /// Generates a public key from the given secret key using the [`crate::DEFAULT_128`]
    /// parameter set.
    ///
    /// # Panics
    /// If the secret key wasn't generated with [`crate::DEFAULT_128`].
    ///
    /// # Examples
    /// ```
    /// use parasol_runtime::{PublicKey, SecretKey};
    ///
    /// let sk = SecretKey::generate_with_default_params();
    /// let pk = PublicKey::generate_with_default_params(&sk);
    /// ```
    pub fn generate_with_default_params(sk: &SecretKey) -> Self {
        Self::generate(&DEFAULT_128, sk)
    }
}

#[derive(Clone, Serialize, Deserialize)]
/// A secret key.
///
/// # Security
/// You should generally never share the [`SecretKey`] with other parties, as they'll be able to
/// decrypt any data encrypted under it.
///
/// # Remarks
/// FHE secret keys are 10s of kB and you should generally serialize them using APIs that provide
/// compact arrays, such as [`bincode`]. JSON is not recommended. Furthermore, you must treat
/// serialized secret keys with the same care as deserialized ones with regards to not sharing them.
pub struct SecretKey {
    /// The internal [`LweSecretKey`] under level-0 parameters.
    pub lwe_0: LweSecretKey<u64>,
    /// The internal [`GlweSecretKey`] under level-1 parameters.
    pub glwe_1: GlweSecretKey<u64>,
}

impl GetSize for SecretKey {
    fn get_size(params: &Params) -> usize {
        // The magic 3 is the length fields of the 3 serialized sequences.
        (LweSecretKeyRef::<u64>::size(params.l0_params.dim)
            + GlweSecretKeyRef::<u64>::size(params.l1_params.dim)
            + 3)
            * size_of::<u64>()
    }

    fn check_is_valid(&self, params: &Params) -> crate::Result<()> {
        self.lwe_0.check_is_valid(params.l0_params.dim)?;
        self.glwe_1.check_is_valid(params.l1_params.dim)?;

        Ok(())
    }
}

impl SecretKey {
    /// Generate a [`SecretKey`] under the given parameter set.
    pub fn generate(params: &Params) -> Self {
        let lwe_0 = keygen::generate_binary_lwe_sk(&params.l0_params);
        let glwe_1 = keygen::generate_binary_glwe_sk(&params.l1_params);

        Self { lwe_0, glwe_1 }
    }

    /// Generate a [`SecretKey`] with the default parameter set
    /// ([`crate::DEFAULT_128`])
    pub fn generate_with_default_params() -> Self {
        Self::generate(&Params::default())
    }

    /// Generate a [`SecretKey`] under the given parameter set with a specific seed.
    ///
    /// # Remarks
    /// The same seed will always produce the same key, making this function deterministic.
    /// This is useful for reproducible testing or when you need to regenerate the same key.
    ///
    /// # Examples
    /// ```
    /// use parasol_runtime::{SecretKey, Seed, DEFAULT_128};
    ///
    /// // Generate a random seed
    /// let seed = Seed::generate();
    ///
    /// // Generate a deterministic key
    /// let sk1 = SecretKey::generate_with_seed(&DEFAULT_128, &seed);
    /// let sk2 = SecretKey::generate_with_seed(&DEFAULT_128, &seed);
    ///
    /// // sk1 and sk2 will be identical
    /// ```
    pub fn generate_with_seed(params: &Params, seed: &Seed) -> Self {
        let (lwe_0, glwe_1) = keygen::generate_binary_lwe_glwe_sk_with_seed(
            &params.l0_params,
            &params.l1_params,
            seed,
        );

        Self { lwe_0, glwe_1 }
    }

    /// Generate a [`SecretKey`] with the default parameter set
    /// ([`crate::DEFAULT_128`]) and a specific seed.
    ///
    /// # Remarks
    /// The same seed will always produce the same key, making this function deterministic.
    ///
    /// # Examples
    /// ```
    /// use parasol_runtime::{SecretKey, Seed};
    ///
    /// let seed = Seed::from_bytes([42u8; 32]);
    /// let sk = SecretKey::generate_with_default_params_and_seed(&seed);
    /// ```
    pub fn generate_with_default_params_and_seed(seed: &Seed) -> Self {
        Self::generate_with_seed(&Params::default(), seed)
    }
}

#[derive(Clone, Serialize, Deserialize)]
/// A set of keys that can be FFT'd and used during evaluation.
///
/// # Remarks
/// Compute keys are quite large (100s of MB), so you should serialize with a protocol that can
/// efficiently store arrays. Additionally, you should design your protocol around not having to
/// frequently share these.
pub struct ComputeKeyNonFft {
    /// The bootstrapping key used internally in circuit bootstrapping operations.
    pub bs_key: BootstrapKey<u64>,

    /// The keyswitch keys for converting L1 LWE ciphertexts to L0 LWE ciphertexts.
    pub ks_key: LweKeyswitchKey<u64>,

    /// An automorphism key used as part of circuit bootstrapping.
    pub auto_key: AutomorphismKey<u64>,

    /// Scheme switching keys used for turning L1 GLEV ciphertexts into L1 GGSW ciphertexts.
    pub ss_key: SchemeSwitchKey<u64>,
}

impl GetSize for ComputeKeyNonFft {
    fn get_size(params: &Params) -> usize {
        let size = BootstrapKeyRef::<u64>::size((
            params.l0_params.dim,
            params.l1_params.dim,
            params.pbs_radix.count,
            params.addend_count,
        ));

        let size = size
            + LweKeyswitchKeyRef::<u64>::size((
                params.l1_params.as_lwe_def().dim,
                params.l0_params.dim,
                params.ks_radix.count,
            ));

        let size =
            size + SchemeSwitchKeyRef::<u64>::size((params.l1_params.dim, params.ss_radix.count));

        let size =
            size + AutomorphismKeyRef::<u64>::size((params.l1_params.dim, params.tr_radix.count));

        // The magic 4 accounts for the fact that we have 4 8-byte lengths, 1 for each
        // key.
        let size = size + 4;

        size * size_of::<u64>()
    }

    fn check_is_valid(&self, params: &Params) -> crate::Result<()> {
        self.bs_key.check_is_valid((
            params.l0_params.dim,
            params.l1_params.dim,
            params.pbs_radix.count,
            params.addend_count,
        ))?;
        self.ks_key.check_is_valid((
            params.l1_params.as_lwe_def().dim,
            params.l0_params.dim,
            params.ks_radix.count,
        ))?;
        self.ss_key
            .check_is_valid((params.l1_params.dim, params.ss_radix.count))?;
        self.auto_key
            .check_is_valid((params.l1_params.dim, params.tr_radix.count))?;

        Ok(())
    }
}

impl ComputeKeyNonFft {
    /// Generate the compute keys in non-fft form from the given secret keys.
    ///
    /// # Remarks
    /// The params passed must be the same as those used during secret key generation.
    pub fn generate(secret_key: &SecretKey, params: &Params) -> Self {
        let bs_key = keygen::generate_bootstrapping_key(
            &secret_key.lwe_0,
            &secret_key.glwe_1,
            &params.l0_params,
            &params.l1_params,
            &params.pbs_radix,
            params.addend_count,
        );

        let ks_key = keygen::generate_ksk(
            secret_key.glwe_1.to_lwe_secret_key(),
            &secret_key.lwe_0,
            &params.l1_params.as_lwe_def(),
            &params.l0_params,
            &params.ks_radix,
        );

        let mut ss_key = SchemeSwitchKey::new(&params.l1_params, &params.ss_radix);

        generate_scheme_switch_key(
            &mut ss_key,
            &secret_key.glwe_1,
            &params.l1_params,
            &params.ss_radix,
        );

        let mut auto_key = AutomorphismKey::new(&params.l1_params, &params.tr_radix);

        generate_automorphism_key(
            &mut auto_key,
            &secret_key.glwe_1,
            &params.l1_params,
            &params.tr_radix,
        );

        Self {
            ks_key,
            bs_key,
            ss_key,
            auto_key,
        }
    }

    /// Takes the fast-fourier transform of the keys, which is used during evaluation.
    pub fn fft(&self, params: &Params) -> ComputeKey {
        let mut ssk_fft = SchemeSwitchKeyFft::new(&params.l1_params, &params.ss_radix);

        self.ss_key
            .fft(&mut ssk_fft, &params.l1_params, &params.ss_radix);

        let mut auto_key_fft = AutomorphismKeyFft::new(&params.l1_params, &params.tr_radix);

        self.auto_key
            .fft(&mut auto_key_fft, &params.l1_params, &params.tr_radix);

        ComputeKey {
            bs_key: fft::fft_bootstrap_key(
                &self.bs_key,
                &params.l0_params,
                &params.l1_params,
                &params.pbs_radix,
                params.addend_count,
            ),
            ks_key: self.ks_key.clone(),
            ss_key: ssk_fft,
            auto_key: auto_key_fft,
        }
    }

    /// Generate the compute keys in non-fft form from the given secret keys with
    /// the default parameters ([`crate::DEFAULT_128`]).
    ///
    /// # Remarks
    /// The secret key must have also been generated with the default parameters.
    pub fn generate_with_default_params(secret_key: &SecretKey) -> Self {
        let params = Params::default();

        Self::generate(secret_key, &params)
    }
}

#[derive(Clone, Serialize, Deserialize)]
/// A set of keys used during FHE evaluation.
///
/// # Remarks
/// - Compute keys are quite large (100s of MB), so you should serialize with a
///   protocol that can efficiently store arrays.
/// - You should design your protocol around not having to frequently share
///   these.
/// - The compute key contains floating point values, which can be represented
///   with insufficient precision when serializing and deserializing across
///   different mediums. Ensure that your key is being serialized and deserialized
///   to the same object.
pub struct ComputeKey {
    /// The FFT'd circuit bootstrap key.
    pub bs_key: BootstrapKeyFft<Complex<f64>>,

    /// The keyswitch keys (not FFT'd).
    pub ks_key: LweKeyswitchKey<u64>,

    /// The FFT'd scheme switch keys.
    pub ss_key: SchemeSwitchKeyFft<Complex<f64>>,

    /// The FFT'd automorphism key.
    pub auto_key: AutomorphismKeyFft<Complex<f64>>,
}

impl GetSize for ComputeKey {
    fn get_size(params: &Params) -> usize {
        let size = BootstrapKeyRef::<u64>::size((
            params.l0_params.dim,
            params.l1_params.dim,
            params.pbs_radix.count,
            params.addend_count,
        ));

        let size = size
            + LweKeyswitchKeyRef::<u64>::size((
                params.l1_params.as_lwe_def().dim,
                params.l0_params.dim,
                params.ks_radix.count,
            ));

        let size =
            size + SchemeSwitchKeyRef::<u64>::size((params.l1_params.dim, params.ss_radix.count));

        let size = size
            + AutomorphismKeyFftRef::<Complex<f64>>::size((
                params.l1_params.dim,
                params.tr_radix.count,
            ));

        // All the keys are FFT'd, so scale the number of elements by the size
        // of each element (a Complex<f64>).
        let size = size * size_of::<Complex<f64>>();

        // The magic 4 accounts for the 4 8-byte length fields, one for each key.
        size + 4 * size_of::<u64>()
    }

    fn check_is_valid(&self, params: &Params) -> crate::Result<()> {
        self.bs_key.check_is_valid((
            params.l0_params.dim,
            params.l1_params.dim,
            params.pbs_radix.count,
            params.addend_count,
        ))?;
        self.ks_key.check_is_valid((
            params.l1_params.as_lwe_def().dim,
            params.l0_params.dim,
            params.ks_radix.count,
        ))?;
        self.ss_key
            .check_is_valid((params.l1_params.dim, params.ss_radix.count))?;
        self.auto_key
            .check_is_valid((params.l1_params.dim, params.tr_radix.count))?;

        Ok(())
    }
}

impl ComputeKey {
    /// Generate the compute keys from the given secret keys.
    ///
    /// # Remarks
    /// The params passed must be the same as those used during secret key generation.
    pub fn generate(secret_key: &SecretKey, params: &Params) -> Self {
        ComputeKeyNonFft::generate(secret_key, params).fft(params)
    }

    /// Generate the compute keys from the given secret keys with default
    /// parameters ([`crate::DEFAULT_128`])
    ///
    /// # Remarks
    /// The secret key must have also been generated with the default parameters.
    pub fn generate_with_default_params(secret_key: &SecretKey) -> Self {
        let params = Params::default();

        Self::generate(secret_key, &params)
    }
}

#[cfg(test)]
mod tests {
    use crate::{DEFAULT_128, SecretKey, Seed};

    // Helper function to compare secret keys by comparing their data
    fn secret_keys_equal(sk1: &SecretKey, sk2: &SecretKey) -> bool {
        // Compare LWE secret key data
        let lwe_equal = sk1.lwe_0.s() == sk2.lwe_0.s();

        // Compare GLWE secret key data using serialization
        let glwe1_bytes = bincode::serialize(&sk1.glwe_1).expect("Failed to serialize GLWE key");
        let glwe2_bytes = bincode::serialize(&sk2.glwe_1).expect("Failed to serialize GLWE key");
        let glwe_equal = glwe1_bytes == glwe2_bytes;

        lwe_equal && glwe_equal
    }

    #[test]
    fn test_secret_key_seeded_deterministic() {
        // Test that the same seed produces identical secret keys
        let seed = Seed::from_bytes([42u8; 32]);

        let sk1 = SecretKey::generate_with_seed(&DEFAULT_128, &seed);
        let sk2 = SecretKey::generate_with_seed(&DEFAULT_128, &seed);

        // Keys should be functionally identical
        assert!(
            secret_keys_equal(&sk1, &sk2),
            "Keys generated from same seed should be identical"
        );
    }

    #[test]
    fn test_secret_key_different_seeds() {
        // Test that different seeds produce different keys
        let seed1 = Seed::from_bytes([1u8; 32]);
        let seed2 = Seed::from_bytes([2u8; 32]);

        let sk1 = SecretKey::generate_with_seed(&DEFAULT_128, &seed1);
        let sk2 = SecretKey::generate_with_seed(&DEFAULT_128, &seed2);

        // Keys should be different (produce different results)
        assert!(!secret_keys_equal(&sk1, &sk2));
    }

    #[test]
    fn test_secret_key_with_default_params_and_seed() {
        // Test the convenience method produces the same key as the full method
        let seed = Seed::from_bytes([123u8; 32]);

        let sk1 = SecretKey::generate_with_default_params_and_seed(&seed);
        let sk2 = SecretKey::generate_with_seed(&DEFAULT_128, &seed);

        // Should be equivalent
        assert!(secret_keys_equal(&sk1, &sk2));
    }
}
