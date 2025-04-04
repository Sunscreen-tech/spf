use num::Complex;
use serde::{Deserialize, Serialize};
use sunscreen_tfhe::{
    entities::{
        GgswCiphertext, GgswCiphertextFft, GgswCiphertextFftRef, GgswCiphertextRef, GlevCiphertext,
        GlevCiphertextRef, GlweCiphertext, GlweCiphertextRef, LweCiphertext, LweCiphertextRef,
        Polynomial, PolynomialRef,
    },
    high_level::encryption::{
        decrypt_ggsw, decrypt_glwe, decrypt_lwe, encrypt_binary_msg_rlev,
        encrypt_binary_msg_secret_glev, trivial_binary_glev, trivial_glwe, trivial_lwe,
    },
    ops::encryption::{decrypt_glev_ciphertext, rlwe_encode_encrypt_public},
    OverlaySize, PlaintextBits, Torus,
};

use crate::{error::Result, fluent::CiphertextOps, params::Params, safe_bincode::GetSize};

use super::{PublicKey, SecretKey, TrivialOne, TrivialZero};
use core::mem::size_of;

#[repr(transparent)]
#[derive(Clone, Serialize, Deserialize)]
pub struct L0LweCiphertext(pub LweCiphertext<u64>);

impl From<LweCiphertext<u64>> for L0LweCiphertext {
    fn from(value: LweCiphertext<u64>) -> Self {
        Self(value)
    }
}

impl TrivialZero for L0LweCiphertext {
    fn trivial_zero(enc: &Encryption) -> Self {
        enc.trivial_lwe_l0_zero()
    }
}

impl TrivialOne for L0LweCiphertext {
    fn trivial_one(enc: &Encryption) -> Self {
        enc.trivial_lwe_l0_one()
    }
}

#[repr(transparent)]
#[derive(Clone, Serialize, Deserialize)]
pub struct L1LweCiphertext(pub LweCiphertext<u64>);

impl From<LweCiphertext<u64>> for L1LweCiphertext {
    fn from(value: LweCiphertext<u64>) -> Self {
        Self(value)
    }
}

impl TrivialZero for L1LweCiphertext {
    fn trivial_zero(enc: &Encryption) -> Self {
        enc.trivial_lwe_l1_zero()
    }
}

impl TrivialOne for L1LweCiphertext {
    fn trivial_one(enc: &Encryption) -> Self {
        enc.trivial_lwe_l1_one()
    }
}

#[repr(transparent)]
#[derive(Clone, Serialize, Deserialize)]
pub struct L1GlweCiphertext(pub GlweCiphertext<u64>);

impl From<GlweCiphertext<u64>> for L1GlweCiphertext {
    fn from(value: GlweCiphertext<u64>) -> Self {
        Self(value)
    }
}

impl TrivialZero for L1GlweCiphertext {
    fn trivial_zero(enc: &Encryption) -> Self {
        enc.trivial_glwe_l1_zero()
    }
}

impl TrivialOne for L1GlweCiphertext {
    fn trivial_one(enc: &Encryption) -> Self {
        enc.trivial_glwe_l1_one()
    }
}

#[repr(transparent)]
#[derive(Clone)]
pub struct L1GgswCiphertext(pub GgswCiphertextFft<Complex<f64>>);

impl From<GgswCiphertextFft<Complex<f64>>> for L1GgswCiphertext {
    fn from(value: GgswCiphertextFft<Complex<f64>>) -> Self {
        Self(value)
    }
}

#[repr(transparent)]
#[derive(Clone, Serialize, Deserialize)]
pub struct L1GlevCiphertext(pub GlevCiphertext<u64>);

impl From<GlevCiphertext<u64>> for L1GlevCiphertext {
    fn from(value: GlevCiphertext<u64>) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone)]
pub struct Encryption {
    pub params: Params,
}

pub const PLAINTEXT_BITS: PlaintextBits = PlaintextBits(1);

impl Encryption {
    pub fn new(params: &Params) -> Self {
        Self {
            params: params.clone(),
        }
    }

    pub fn allocate_lwe_l0(&self) -> L0LweCiphertext {
        LweCiphertext::new(&self.params.l0_params).into()
    }

    pub fn allocate_lwe_l1(&self) -> L1LweCiphertext {
        LweCiphertext::new(&self.params.l1_params.as_lwe_def()).into()
    }

    pub fn allocate_ggsw_l1(&self) -> L1GgswCiphertext {
        GgswCiphertextFft::new(&self.params.l1_params, &self.params.cbs_radix).into()
    }

    pub fn allocate_glwe_l1(&self) -> L1GlweCiphertext {
        GlweCiphertext::new(&self.params.l1_params).into()
    }

    pub fn allocate_glev_l1(&self) -> L1GlevCiphertext {
        GlevCiphertext::new(&self.params.l1_params, &self.params.cbs_radix).into()
    }

    pub fn encrypt_lwe_l0_secret(&self, value: bool, sk: &SecretKey) -> L0LweCiphertext {
        sk.lwe_0
            .encrypt(value as u64, &self.params.l0_params, PLAINTEXT_BITS)
            .0
            .into()
    }

    pub fn encrypt_lwe_l1_secret(&self, value: bool, sk: &SecretKey) -> L1LweCiphertext {
        sk.glwe_1
            .to_lwe_secret_key()
            .encrypt(
                value as u64,
                &self.params.l1_params.as_lwe_def(),
                PLAINTEXT_BITS,
            )
            .0
            .into()
    }

    pub fn encrypt_glwe_l1_secret(
        &self,
        poly: &PolynomialRef<u64>,
        sk: &SecretKey,
    ) -> L1GlweCiphertext {
        sk.glwe_1
            .encode_encrypt_glwe(poly, &self.params.l1_params, PLAINTEXT_BITS)
            .into()
    }

    pub fn encrypt_rlwe_l1(&self, msg: &PolynomialRef<u64>, pk: &PublicKey) -> L1GlweCiphertext {
        let mut ct = L1GlweCiphertext::allocate(&self);

        rlwe_encode_encrypt_public(
            &mut ct.0,
            msg,
            &pk.rlwe_1,
            &PlaintextBits(1),
            &self.params.l1_params,
        );

        ct
    }

    pub fn encrypt_glev_l1_secret(
        &self,
        poly: &PolynomialRef<u64>,
        sk: &SecretKey,
    ) -> L1GlevCiphertext {
        encrypt_binary_msg_secret_glev(
            poly,
            &sk.glwe_1,
            &self.params.l1_params,
            &self.params.cbs_radix,
        )
        .into()
    }

    pub fn encrypt_rlev_l1(&self, poly: &PolynomialRef<u64>, pk: &PublicKey) -> L1GlevCiphertext {
        encrypt_binary_msg_rlev(
            poly,
            &pk.rlwe_1,
            &self.params.l1_params,
            &self.params.cbs_radix,
        )
        .into()
    }

    pub fn encrypt_ggsw_l1_secret(&self, msg: bool, sk: &SecretKey) -> L1GgswCiphertext {
        let mut poly = Polynomial::new(&vec![0u64; self.params.l1_params.dim.polynomial_degree.0]);
        poly.coeffs_mut()[0] = msg as u64;

        let mut ggsw_fft = self.allocate_ggsw_l1();

        sk.glwe_1
            .encode_encrypt_ggsw(
                &poly,
                &self.params.l1_params,
                &self.params.cbs_radix,
                PLAINTEXT_BITS,
            )
            .fft(
                &mut ggsw_fft.0,
                &self.params.l1_params,
                &self.params.cbs_radix,
            );

        ggsw_fft
    }

    pub fn decrypt_lwe_l0(&self, input: &L0LweCiphertext, sk: &SecretKey) -> bool {
        decrypt_lwe(&input.0, &sk.lwe_0, &self.params.l0_params, PLAINTEXT_BITS) == 1
    }

    pub fn decrypt_lwe_l1(&self, input: &L1LweCiphertext, sk: &SecretKey) -> bool {
        decrypt_lwe(
            &input.0,
            sk.glwe_1.to_lwe_secret_key(),
            &self.params.l1_params.as_lwe_def(),
            PLAINTEXT_BITS,
        ) == 1
    }

    pub fn decrypt_ggsw_l1(&self, input: &L1GgswCiphertext, sk: &SecretKey) -> bool {
        let mut ggsw = GgswCiphertext::<u64>::new(&self.params.l1_params, &self.params.cbs_radix);

        input
            .0
            .ifft(&mut ggsw, &self.params.l1_params, &self.params.cbs_radix);

        let poly = decrypt_ggsw(
            &ggsw,
            &sk.glwe_1,
            &self.params.l1_params,
            &self.params.cbs_radix,
            PLAINTEXT_BITS,
        );

        poly.coeffs()[0] == 1
    }

    pub fn decrypt_glwe_l1(&self, ct: &L1GlweCiphertext, sk: &SecretKey) -> Polynomial<u64> {
        decrypt_glwe(&ct.0, &sk.glwe_1, &self.params.l1_params, PLAINTEXT_BITS)
    }

    pub fn decrypt_glev_l1(&self, ct: &L1GlevCiphertext, sk: &SecretKey) -> Polynomial<u64> {
        let mut msg = Polynomial::<Torus<u64>>::zero(self.params.l1_params.dim.polynomial_degree.0);

        decrypt_glev_ciphertext(
            &mut msg,
            &ct.0,
            &sk.glwe_1,
            &self.params.l1_params,
            &self.params.cbs_radix,
        );

        msg.map(|x| x.inner())
    }

    pub fn trivial_glwe_l1_zero(&self) -> L1GlweCiphertext {
        let zero = Polynomial::zero(self.params.l1_poly_degree().0);

        self.trivial_glwe_l1(&zero)
    }

    pub fn trivial_glwe_l1_one(&self) -> L1GlweCiphertext {
        let mut one = Polynomial::zero(self.params.l1_poly_degree().0);
        one.coeffs_mut()[0] = 1;

        self.trivial_glwe_l1(&one)
    }

    pub fn trivial_glwe_l1(&self, pt: &PolynomialRef<u64>) -> L1GlweCiphertext {
        trivial_glwe(pt, &self.params.l1_params, PLAINTEXT_BITS).into()
    }

    pub fn trivial_lwe_l0_zero(&self) -> L0LweCiphertext {
        trivial_lwe(0, &self.params.l0_params, PLAINTEXT_BITS).into()
    }

    pub fn trivial_lwe_l0_one(&self) -> L0LweCiphertext {
        trivial_lwe(1, &self.params.l0_params, PLAINTEXT_BITS).into()
    }

    pub fn trivial_lwe_l1_zero(&self) -> L1LweCiphertext {
        trivial_lwe(0, &self.params.l1_params.as_lwe_def(), PLAINTEXT_BITS).into()
    }

    pub fn trivial_lwe_l1_one(&self) -> L1LweCiphertext {
        trivial_lwe(1, &self.params.l1_params.as_lwe_def(), PLAINTEXT_BITS).into()
    }

    pub fn trivial_glev_l1_zero(&self) -> L1GlevCiphertext {
        GlevCiphertext::new(&self.params.l1_params, &self.params.cbs_radix).into()
    }

    pub fn trivial_glev_l1_one(&self) -> L1GlevCiphertext {
        let mut msg = Polynomial::zero(self.params.l1_poly_degree().0);
        msg.coeffs_mut()[0] = 1;

        trivial_binary_glev(&mut msg, &self.params.l1_params, &self.params.cbs_radix).into()
    }
}

impl Default for Encryption {
    fn default() -> Self {
        Self {
            params: Params::default(),
        }
    }
}

impl GetSize for L0LweCiphertext {
    fn get_size(params: &Params) -> usize {
        (LweCiphertextRef::<u64>::size(params.l0_params.dim) + 1) * size_of::<u64>()
    }

    fn check_is_valid(&self, params: &Params) -> Result<()> {
        Ok(LweCiphertextRef::<u64>::check_is_valid(
            &self.0,
            params.l0_params.dim,
        )?)
    }
}

impl GetSize for L1LweCiphertext {
    fn get_size(params: &Params) -> usize {
        (LweCiphertextRef::<u64>::size(params.l1_params.as_lwe_def().dim) + 1) * size_of::<u64>()
    }

    fn check_is_valid(&self, params: &Params) -> Result<()> {
        Ok(LweCiphertextRef::<u64>::check_is_valid(
            &self.0,
            params.l1_params.as_lwe_def().dim,
        )?)
    }
}

impl GetSize for L1GlweCiphertext {
    fn get_size(params: &Params) -> usize {
        (GlweCiphertextRef::<u64>::size(params.l1_params.dim) + 1) * size_of::<u64>()
    }

    fn check_is_valid(&self, params: &Params) -> Result<()> {
        Ok(GlweCiphertextRef::<u64>::check_is_valid(
            &self.0,
            params.l1_params.dim,
        )?)
    }
}

impl GetSize for L1GgswCiphertext {
    fn get_size(params: &Params) -> usize {
        (GgswCiphertextRef::<u64>::size((params.l1_params.dim, params.cbs_radix.count)) + 1)
            * size_of::<u64>()
    }

    fn check_is_valid(&self, params: &Params) -> Result<()> {
        Ok(GgswCiphertextFftRef::<Complex<f64>>::check_is_valid(
            &self.0,
            (params.l1_params.dim, params.cbs_radix.count),
        )?)
    }
}

impl GetSize for L1GlevCiphertext {
    fn get_size(params: &Params) -> usize {
        (GlevCiphertextRef::<u64>::size((params.l1_params.dim, params.cbs_radix.count)) + 1)
            * size_of::<u64>()
    }

    fn check_is_valid(&self, params: &Params) -> Result<()> {
        Ok(GlevCiphertextRef::<u64>::check_is_valid(
            &self.0,
            (params.l1_params.dim, params.cbs_radix.count),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{params::DEFAULT_80, test_utils::get_secret_keys_80};

    use super::*;

    #[test]
    fn can_roundtrip_l0_lwe() {
        let sk = get_secret_keys_80();
        let enc = Encryption::new(&DEFAULT_80);

        let lwe = enc.encrypt_lwe_l0_secret(false, &sk);
        assert!(!enc.decrypt_lwe_l0(&lwe, &sk));

        let lwe = enc.encrypt_lwe_l0_secret(true, &sk);
        assert!(enc.decrypt_lwe_l0(&lwe, &sk));
    }

    #[test]
    fn can_roundtrip_l1_lwe() {
        let sk = get_secret_keys_80();
        let enc = Encryption::new(&DEFAULT_80);

        let lwe = enc.encrypt_lwe_l1_secret(false, &sk);
        assert!(!enc.decrypt_lwe_l1(&lwe, &sk));

        let lwe = enc.encrypt_lwe_l1_secret(true, &sk);
        assert!(enc.decrypt_lwe_l1(&lwe, &sk));
    }

    #[test]
    fn trivial_zero_glwe1() {
        let secret = get_secret_keys_80();
        let enc = Encryption::new(&DEFAULT_80);

        let zero = enc.trivial_glwe_l1_zero();

        let actual = enc.decrypt_glwe_l1(&zero, &secret);
        let expected = Polynomial::zero(DEFAULT_80.l1_poly_degree().0);

        assert_eq!(actual, expected);
    }

    #[test]
    fn trivial_one_glwe1() {
        let secret = get_secret_keys_80();
        let enc = Encryption::new(&DEFAULT_80);

        let zero = enc.trivial_glwe_l1_one();

        let actual = enc.decrypt_glwe_l1(&zero, &secret);
        let mut expected = Polynomial::zero(DEFAULT_80.l1_poly_degree().0);
        expected.coeffs_mut()[0] = 1;

        assert_eq!(actual, expected);
    }

    #[test]
    fn trivial_zero_lwe0() {
        let secret = get_secret_keys_80();
        let enc = Encryption::new(&DEFAULT_80);

        let zero = enc.trivial_lwe_l0_zero();

        let actual = enc.decrypt_lwe_l0(&zero, &secret);

        assert_eq!(actual, false);
    }

    #[test]
    fn trivial_one_lwe0() {
        let secret = get_secret_keys_80();
        let enc = Encryption::new(&DEFAULT_80);

        let one = enc.trivial_lwe_l0_one();

        let actual = enc.decrypt_lwe_l0(&one, &secret);

        assert_eq!(actual, true);
    }

    #[test]
    fn trivial_zero_glev1() {
        let secret = get_secret_keys_80();
        let enc = Encryption::new(&DEFAULT_80);

        let one = enc.trivial_glev_l1_zero();

        let actual = enc.decrypt_glev_l1(&one, &secret);

        assert_eq!(actual, Polynomial::zero(DEFAULT_80.l1_poly_degree().0));
    }

    #[test]
    fn trivial_one_glev1() {
        let secret = get_secret_keys_80();
        let enc = Encryption::new(&DEFAULT_80);

        let one = enc.trivial_glev_l1_one();

        let actual = enc.decrypt_glev_l1(&one, &secret);

        let mut expected = Polynomial::zero(DEFAULT_80.l1_poly_degree().0);
        expected.coeffs_mut()[0] = 1;

        assert_eq!(actual, expected);
    }
}
