use std::marker::PhantomData;

use sunscreen_tfhe::entities::Polynomial;

use crate::{
    Encryption, L1GlweCiphertext, SecretKey,
    crypto::SecretOneTimePad,
    decrypt_one_time_pad,
    fluent::generic_int::PlaintextOps,
    fluent::{Sign, Signed, Unsigned},
};

/// A GLWE-encrypted packed integer that has undergone [`recryption`](crate::recryption)`.
pub struct EncryptedRecryptedGenricInt<U: Sign> {
    bit_len: u32,
    inner: L1GlweCiphertext,
    _phantom: PhantomData<U>,
}

impl<U: Sign> EncryptedRecryptedGenricInt<U> {
    pub(crate) fn new(bit_len: u32, ct: L1GlweCiphertext) -> Self {
        Self {
            bit_len,
            inner: ct,
            _phantom: PhantomData,
        }
    }

    /// Remove the layer of GLWE encryption, resulting in a one-time-pad
    /// encrypted [`RecryptedGenericInt`].
    pub fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> RecryptedGenericInt<U> {
        RecryptedGenericInt {
            bit_len: self.bit_len,
            inner: enc.decrypt_glwe_l1(&self.inner, sk),
            _phantom: PhantomData,
        }
    }
}

/// A one-time-pad encrypted integer.
pub struct RecryptedGenericInt<U: Sign> {
    bit_len: u32,
    inner: Polynomial<u64>,
    _phantom: PhantomData<U>,
}

impl<U: Sign> RecryptedGenericInt<U> {
    /// Decrypt the contained integer using the given [`SecretOneTimePad`].
    ///
    /// # Remarks
    /// End users produce a [`SecretOneTimePad`] by calling
    /// [`crate::generate_one_time_pad`]. This object is secret and must not
    /// be shared.
    pub fn decrypt(&self, otp: &SecretOneTimePad) -> U::PlaintextType {
        assert!((self.bit_len as usize) <= self.inner.len());

        let poly = decrypt_one_time_pad(&self.inner, otp);

        U::PlaintextType::from_bits(
            poly.coeffs()
                .iter()
                .map(|x| *x == 1)
                .take(self.bit_len as usize),
        )
    }
}

/// A [`recrypted`](crate::recryption) signed integer.
pub type RecryptedInt = RecryptedGenericInt<Signed>;
/// A [`recrypted`](crate::recryption) unsigned integer.
pub type RecryptedUInt = RecryptedGenericInt<Unsigned>;
/// A [`recrypted`](crate::recryption) signed integer encrypted under an FHE key.
pub type EncryptedRecryptedInt = EncryptedRecryptedGenricInt<Signed>;
/// A [`recrypted`](crate::recryption) unsigned integer encrypted under an FHE key.
pub type EncryptedRecryptedUInt = EncryptedRecryptedGenricInt<Unsigned>;

#[cfg(test)]
mod tests {
    use crate::{
        DEFAULT_128, KeylessEvaluation, PublicKey,
        fluent::{PackedInt32, PackedUInt32},
        generate_one_time_pad,
        test_utils::{get_encryption_128, get_secret_keys_128},
    };

    #[test]
    fn recrypt_signed() {
        let enc = get_encryption_128();
        let eval = KeylessEvaluation::new(&DEFAULT_128, &enc);
        let sk = get_secret_keys_128();
        let pk = PublicKey::generate(&DEFAULT_128, &sk);

        let val = PackedInt32::encrypt(-42i128, &enc, &pk);

        let (pub_otp, priv_otp) = generate_one_time_pad(&DEFAULT_128, &enc, &pk);

        let t = val.recrypt(&enc, &eval, &pub_otp);
        let t = t.decrypt(&enc, &sk);
        let actual = t.decrypt(&priv_otp);

        assert_eq!(actual, -42);
    }

    #[test]
    fn recrypt_unsigned() {
        let enc = get_encryption_128();
        let eval = KeylessEvaluation::new(&DEFAULT_128, &enc);
        let sk = get_secret_keys_128();
        let pk = PublicKey::generate(&DEFAULT_128, &sk);

        let val = PackedUInt32::encrypt(42, &enc, &pk);

        let (pub_otp, priv_otp) = generate_one_time_pad(&DEFAULT_128, &enc, &pk);

        let t = val.recrypt(&enc, &eval, &pub_otp);
        let t = t.decrypt(&enc, &sk);
        let actual = t.decrypt(&priv_otp);

        assert_eq!(actual, 42);
    }
}
