use num::Complex;
use serde::{Deserialize, Serialize};
use std::mem::size_of;
use sunscreen_tfhe::entities::{
    BootstrapKey, BootstrapKeyFft, BootstrapKeyRef, CircuitBootstrappingKeyswitchKeys,
    CircuitBootstrappingKeyswitchKeysRef, GlweSecretKey, GlweSecretKeyRef, LweKeyswitchKey,
    LweKeyswitchKeyRef, LweSecretKey, LweSecretKeyRef, RlwePublicKey, RlwePublicKeyRef,
    SchemeSwitchKey, SchemeSwitchKeyFft, SchemeSwitchKeyRef,
};
use sunscreen_tfhe::high_level::{fft, keygen};
use sunscreen_tfhe::ops::bootstrapping::generate_scheme_switch_key;
use sunscreen_tfhe::ops::encryption::rlwe_generate_public_key;
use sunscreen_tfhe::OverlaySize;

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
    pub fn generate(params: &Params, sk: &SecretKey) -> Self {
        assert_eq!(params.l1_params.dim.size.0, 1, "Unfortunately, public keys currently require a GLWE size of 1. This restriction will likely be eased in the future.");

        let mut pk = RlwePublicKey::new(&params.l1_params);

        rlwe_generate_public_key(&mut pk, &sk.glwe_1, &params.l1_params);

        Self { rlwe_1: pk }
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
    /// The internal [`GlweSecretKey`] under level-2 parameters.
    pub glwe_2: GlweSecretKey<u64>,
}

impl GetSize for SecretKey {
    fn get_size(params: &Params) -> usize {
        // The magic 3 is the length fields of the 3 serialized sequences.
        (LweSecretKeyRef::<u64>::size(params.l0_params.dim)
            + GlweSecretKeyRef::<u64>::size(params.l1_params.dim)
            + GlweSecretKeyRef::<u64>::size(params.l2_params.dim)
            + 3)
            * size_of::<u64>()
    }

    fn check_is_valid(&self, params: &Params) -> crate::Result<()> {
        self.lwe_0.check_is_valid(params.l0_params.dim)?;
        self.glwe_1.check_is_valid(params.l1_params.dim)?;
        self.glwe_2.check_is_valid(params.l2_params.dim)?;

        Ok(())
    }
}

impl SecretKey {
    /// Generate a [`SecretKey`] under the given parameter set.
    pub fn generate(params: &Params) -> Self {
        let lwe_0 = keygen::generate_binary_lwe_sk(&params.l0_params);
        let glwe_1 = keygen::generate_binary_glwe_sk(&params.l1_params);
        let glwe_2 = keygen::generate_binary_glwe_sk(&params.l2_params);

        Self {
            lwe_0,
            glwe_1,
            glwe_2,
        }
    }

    /// Generate a [`SecretKey`] with the default parameter set
    /// ([`crate::DEFAULT_128`])
    pub fn generate_with_default_params() -> Self {
        Self::generate(&Params::default())
    }
}

#[derive(Clone, Serialize, Deserialize)]
/// A set of keys that can be FFT'd and used during evaluation.
///
/// # Remarks
/// Server keys are quite large (100s of MB), so you should serialize with a protocol that can
/// efficiently store arrays. Additionally, you should design your protocol around not having to
/// frequently share these.
pub struct ServerKeyNonFft {
    /// The boostrapping key used internally in circuit bootstrapping operations.
    pub cbs_key: BootstrapKey<u64>,

    /// The private functional keyswitch keys used internally during circuit bootstrapping.
    pub pfks_key: CircuitBootstrappingKeyswitchKeys<u64>,

    /// The keyswitch keys for converting L1 LWE ciphertexts to L0 LWE ciphertexts.
    pub ks_key: LweKeyswitchKey<u64>,

    /// Scheme switching keys used for turning L1 GLEV ciphertexts into L1 GGSW ciphertexts.
    pub ss_key: SchemeSwitchKey<u64>,
}

impl GetSize for ServerKeyNonFft {
    fn get_size(params: &Params) -> usize {
        // The magic 4 is the lengths of the 4 serialized sequences.
        (BootstrapKeyRef::<u64>::size((
            params.l0_params.dim,
            params.l2_params.dim,
            params.pbs_radix.count,
        )) + CircuitBootstrappingKeyswitchKeysRef::<u64>::size((
            params.l2_params.as_lwe_def().dim,
            params.l1_params.dim,
            params.pfks_radix.count,
        )) + LweKeyswitchKeyRef::<u64>::size((
            params.l1_params.as_lwe_def().dim,
            params.l0_params.dim,
            params.ks_radix.count,
        )) + SchemeSwitchKeyRef::<u64>::size((params.l1_params.dim, params.ss_radix.count))
            + 4)
            * size_of::<u64>()
    }

    fn check_is_valid(&self, params: &Params) -> crate::Result<()> {
        self.cbs_key.check_is_valid((
            params.l0_params.dim,
            params.l2_params.dim,
            params.pbs_radix.count,
        ))?;
        self.pfks_key.check_is_valid((
            params.l2_params.as_lwe_def().dim,
            params.l1_params.dim,
            params.pfks_radix.count,
        ))?;
        self.ks_key.check_is_valid((
            params.l1_params.as_lwe_def().dim,
            params.l0_params.dim,
            params.ks_radix.count,
        ))?;
        self.ss_key
            .check_is_valid((params.l1_params.dim, params.ss_radix.count))?;

        Ok(())
    }
}

impl ServerKeyNonFft {
    /// Generate the server keys in non-fft form from the given secret keys.
    ///
    /// # Remarks
    /// The params passed must be the same as those used during secret key generation.
    pub fn generate(secret_key: &SecretKey, params: &Params) -> Self {
        let cbs_key = keygen::generate_bootstrapping_key(
            &secret_key.lwe_0,
            &secret_key.glwe_2,
            &params.l0_params,
            &params.l2_params,
            &params.pbs_radix,
        );

        let ks_key = keygen::generate_ksk(
            secret_key.glwe_1.to_lwe_secret_key(),
            &secret_key.lwe_0,
            &params.l1_params.as_lwe_def(),
            &params.l0_params,
            &params.ks_radix,
        );

        let pfks_key = keygen::generate_cbs_ksk(
            secret_key.glwe_2.to_lwe_secret_key(),
            &secret_key.glwe_1,
            &params.l2_params.as_lwe_def(),
            &params.l1_params,
            &params.pfks_radix,
        );

        let mut ss_key = SchemeSwitchKey::new(&params.l1_params, &params.ss_radix);

        generate_scheme_switch_key(
            &mut ss_key,
            &secret_key.glwe_1,
            &params.l1_params,
            &params.ss_radix,
        );

        Self {
            ks_key,
            cbs_key,
            pfks_key,
            ss_key,
        }
    }

    /// Takes the fast-fourier transform of the keys, which is used during evaluation.
    pub fn fft(&self, params: &Params) -> ServerKey {
        let mut ssk_fft = SchemeSwitchKeyFft::new(&params.l1_params, &params.ss_radix);

        self.ss_key
            .fft(&mut ssk_fft, &params.l1_params, &params.ss_radix);

        ServerKey {
            cbs_key: fft::fft_bootstrap_key(
                &self.cbs_key,
                &params.l0_params,
                &params.l2_params,
                &params.cbs_radix,
            ),
            pfks_key: self.pfks_key.clone(),
            ks_key: self.ks_key.clone(),
            ss_key: ssk_fft,
        }
    }

    /// Generate the server keys from the given secret keys in FFT form.
    ///
    /// # Remarks
    /// The params passed must be the same as those used during secret key generation.
    pub fn generate_fft(secret_key: &SecretKey, params: &Params) -> ServerKey {
        Self::generate(secret_key, params).fft(params)
    }

    /// Generate the server keys from the given secret keys in FFT form with
    /// default parameters ([`crate::DEFAULT_128`]).
    pub fn generate_fft_with_default_params(secret_key: &SecretKey) -> ServerKey {
        let params = &Params::default();
        Self::generate(secret_key, params).fft(params)
    }
}

#[derive(Clone, Serialize, Deserialize)]
/// A set of keys used during FHE evaluation.
///
/// # Remarks
/// - Server keys are quite large (100s of MB), so you should serialize with a
///   protocol that can efficiently store arrays.
/// - You should design your protocol around not having to frequently share
///   these.
/// - The server key contains floating point values, which can be represented
///   with insufficient precision when serializing and deserializing across
///   different mediums. Ensure that your key is being serialized and deserialized
///   to the same object.
pub struct ServerKey {
    /// The FFT'd circuit bootstrap key.
    pub cbs_key: BootstrapKeyFft<Complex<f64>>,

    /// The private function keyswitch keys (not FFT'd).
    pub pfks_key: CircuitBootstrappingKeyswitchKeys<u64>,

    /// The keyswitch keys (not FFT'd).
    pub ks_key: LweKeyswitchKey<u64>,

    /// The FFT'd scheme switch keys.
    pub ss_key: SchemeSwitchKeyFft<Complex<f64>>,
}

impl GetSize for ServerKey {
    fn get_size(params: &Params) -> usize {
        // The magic 4 is the lengths of the 4 serialized sequences.
        (BootstrapKeyRef::<u64>::size((
            params.l0_params.dim,
            params.l2_params.dim,
            params.pbs_radix.count,
        )) + CircuitBootstrappingKeyswitchKeysRef::<u64>::size((
            params.l2_params.as_lwe_def().dim,
            params.l1_params.dim,
            params.pfks_radix.count,
        )) + LweKeyswitchKeyRef::<u64>::size((
            params.l1_params.as_lwe_def().dim,
            params.l0_params.dim,
            params.ks_radix.count,
        )) + SchemeSwitchKeyRef::<u64>::size((params.l1_params.dim, params.ss_radix.count)))
            * size_of::<Complex<f64>>()
            + 4 * size_of::<u64>()
    }

    fn check_is_valid(&self, params: &Params) -> crate::Result<()> {
        self.cbs_key.check_is_valid((
            params.l0_params.dim,
            params.l2_params.dim,
            params.pbs_radix.count,
        ))?;
        self.pfks_key.check_is_valid((
            params.l2_params.as_lwe_def().dim,
            params.l1_params.dim,
            params.pfks_radix.count,
        ))?;
        self.ks_key.check_is_valid((
            params.l1_params.as_lwe_def().dim,
            params.l0_params.dim,
            params.ks_radix.count,
        ))?;
        self.ss_key
            .check_is_valid((params.l1_params.dim, params.ss_radix.count))?;

        Ok(())
    }
}

impl ServerKey {
    /// Generate the server keys from the given secret keys.
    ///
    /// # Remarks
    /// The params passed must be the same as those used during secret key generation.
    pub fn generate(secret_key: &SecretKey, params: &Params) -> Self {
        ServerKeyNonFft::generate(secret_key, params).fft(params)
    }
}
