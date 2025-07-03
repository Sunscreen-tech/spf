use crate::{
    Encryption, KeylessEvaluation, L1GlweCiphertext, Params, PublicKey, safe_bincode::GetSize,
};
use rand::{RngCore, thread_rng};
use serde::{Deserialize, Serialize};
use sunscreen_tfhe::{
    OverlaySize,
    entities::{Polynomial, PolynomialRef},
};

#[derive(Clone, Serialize, Deserialize)]
/// The encrypted version of a one-time-pad.
///
/// # Remarks
/// This is a one-time pad encrypted under a GLWE key that one shares with a third party.
/// That party can then take an existing GLWE ciphertext and add it to this. When the result
/// is then decrypted (e.g. via a threshold committee), the resulting message will itself be
/// encrypted under the [`SecretOneTimePad`] key.
///
/// # Security
/// As the name implies, one must never use a one-time pad more than once; you must generate a
/// new one for each GLWE ciphertext you wish to recrypt.
pub struct PublicOneTimePad {
    ct: L1GlweCiphertext,
}

impl GetSize for PublicOneTimePad {
    fn check_is_valid(&self, params: &Params) -> crate::Result<()> {
        L1GlweCiphertext::check_is_valid(&self.ct, params)
    }

    fn get_size(params: &Params) -> usize {
        L1GlweCiphertext::get_size(params)
    }
}

#[derive(Clone, Serialize, Deserialize)]
/// The secret key for a one-time-pad.
///
/// # Security
/// A given one-time-pad must never recrypt more than one message.
/// This object is secret and must not be shared with other parties.
pub struct SecretOneTimePad {
    key: Polynomial<u64>,
}

impl GetSize for SecretOneTimePad {
    fn check_is_valid(&self, params: &Params) -> crate::Result<()> {
        Ok(PolynomialRef::check_is_valid(
            &self.key,
            params.l1_params.dim.polynomial_degree,
        )?)
    }

    fn get_size(params: &Params) -> usize {
        // +1 for the length counter in the bincode buffer.
        (PolynomialRef::<u64>::size(params.l1_poly_degree()) + 1) * size_of::<u64>()
    }
}

/// Generates a [`PublicOneTimePad`], [`SecretOneTimePad`] pair. Give the public
/// version to the party to perform recryption and use the secret version to
/// decrypt the contained message.
///
/// # Security
/// See [`SecretOneTimePad`]'s security section.
pub fn generate_one_time_pad(
    params: &Params,
    enc: &Encryption,
    pk: &PublicKey,
) -> (PublicOneTimePad, SecretOneTimePad) {
    let key = Polynomial::new(
        &(0..params.l1_poly_degree().0)
            .map(|_| thread_rng().next_u64() % 2)
            .collect::<Vec<_>>(),
    );
    let secret = SecretOneTimePad { key };

    let ct = enc.encrypt_rlwe_l1(&secret.key, pk);
    let public = PublicOneTimePad { ct };

    (public, secret)
}

/// Perform one-time pad recryption. The result GLWE ciphertext contains the message in
/// `x` xor'd with `otp.key`, and is thus a one-time pad. After the resulting GLWE ciphertext is
/// decrypted, the holder of the [`SecretOneTimePad`] can then decrypt the result.
pub fn recrypt_one_time_pad(
    x: &L1GlweCiphertext,
    otp: &PublicOneTimePad,
    eval: &KeylessEvaluation,
    enc: &Encryption,
) -> L1GlweCiphertext {
    let mut result = enc.allocate_glwe_l1();

    eval.xor(&mut result, x, &otp.ct);

    result
}

/// Given a [`SecretOneTimePad`], decrypt the resulting message.
pub fn decrypt_one_time_pad(x: &PolynomialRef<u64>, sk: &SecretOneTimePad) -> Polynomial<u64> {
    assert_eq!(sk.key.len(), x.len());

    let mut result = Polynomial::new(&vec![0; x.len()]);

    for (c, (a, b)) in result
        .coeffs_mut()
        .iter_mut()
        .zip(x.coeffs().iter().zip(sk.key.coeffs()))
    {
        *c = (a + b) % 2;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DEFAULT_128, KeylessEvaluation, PublicKey, safe_bincode,
        test_utils::{get_encryption_128, get_secret_keys_128},
    };

    #[test]
    fn can_recrypt() {
        let enc = get_encryption_128();
        let eval = KeylessEvaluation::new(&DEFAULT_128, &enc);
        let sk = get_secret_keys_128();
        let pk = PublicKey::generate(&DEFAULT_128, &sk);

        let expected = Polynomial::new(
            &(0..DEFAULT_128.l1_poly_degree().0)
                .map(|_| thread_rng().next_u64() % 2)
                .collect::<Vec<_>>(),
        );

        let ct = enc.encrypt_rlwe_l1(&expected, &pk);

        let (public_otp, secret_otp) = generate_one_time_pad(&DEFAULT_128, &enc, &pk);

        let recrypted = recrypt_one_time_pad(&ct, &public_otp, &eval, &enc);

        let otp_encrypted = enc.decrypt_glwe_l1(&recrypted, &sk);
        let actual = decrypt_one_time_pad(&otp_encrypted, &secret_otp);

        assert_eq!(actual, expected);
    }

    #[test]
    fn safe_deserialize_public_otp() {
        let result =
            safe_bincode::deserialize::<PublicOneTimePad>(&[1, 2, 3, 4, 5, 6], &DEFAULT_128);

        assert!(result.is_err());

        let enc = get_encryption_128();
        let sk = get_secret_keys_128();
        let pk = PublicKey::generate(&DEFAULT_128, &sk);

        let (public, _) = generate_one_time_pad(&DEFAULT_128, &enc, &pk);

        let data = bincode::serialize(&public).unwrap();
        let result = safe_bincode::deserialize::<PublicOneTimePad>(&data, &DEFAULT_128).unwrap();

        assert_eq!(result.ct.0, public.ct.0);
    }

    #[test]
    fn safe_deserialize_secret_otp() {
        let result =
            safe_bincode::deserialize::<SecretOneTimePad>(&[1, 2, 3, 4, 5, 6], &DEFAULT_128);

        assert!(result.is_err());

        let enc = get_encryption_128();
        let sk = get_secret_keys_128();
        let pk = PublicKey::generate(&DEFAULT_128, &sk);

        let (_, secret) = generate_one_time_pad(&DEFAULT_128, &enc, &pk);

        let data = bincode::serialize(&secret).unwrap();
        let result = safe_bincode::deserialize::<SecretOneTimePad>(&data, &DEFAULT_128).unwrap();

        assert_eq!(result.key, secret.key);
    }
}
