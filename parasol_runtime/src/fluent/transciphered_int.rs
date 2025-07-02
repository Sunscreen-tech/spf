use std::marker::PhantomData;

use sunscreen_tfhe::entities::Polynomial;

use crate::{
    Encryption, L1GlweCiphertext, SecretKey,
    crypto::SecretOneTimePad,
    decrypt_one_time_pad,
    fluent::{Sign, Signed, Unsigned},
};

/// A GLWE-encrypted packed integer that has undergone transciphering.
pub struct EncryptedTranscipheredInt<U: Sign> {
    bit_len: u32,
    inner: L1GlweCiphertext,
    _phantom: PhantomData<U>,
}

impl<U: Sign> EncryptedTranscipheredInt<U> {
    pub(crate) fn new(bit_len: u32, ct: L1GlweCiphertext) -> Self {
        Self {
            bit_len,
            inner: ct,
            _phantom: PhantomData,
        }
    }

    /// Remove the layer of GLWE encryption, resulting in a one-time-pad
    /// encrypted [`TranscipheredInt`].
    pub fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> TranscipheredInt<U> {
        TranscipheredInt {
            bit_len: self.bit_len,
            inner: enc.decrypt_glwe_l1(&self.inner, sk),
            _phantom: PhantomData,
        }
    }
}

/// A one-time-pad encrypted integer.
pub struct TranscipheredInt<U: Sign> {
    bit_len: u32,
    inner: Polynomial<u64>,
    _phantom: PhantomData<U>,
}

impl<U: Sign> TranscipheredInt<U> {
    fn decrypt_inner(&self, otp: &SecretOneTimePad) -> u128 {
        assert!((self.bit_len as usize) < self.inner.len());
        let mut val = 0u128;

        let poly = decrypt_one_time_pad(&self.inner, otp);

        for i in 0..self.bit_len as usize {
            val += (poly.coeffs()[i] as u128) << i;
        }

        val
    }
}

impl TranscipheredInt<Signed> {
    /// Decrypt the contained integer using the given [`SecretOneTimePad`].
    pub fn decrypt(&self, otp: &SecretOneTimePad) -> i128 {
        let mut val = self.decrypt_inner(otp);

        // Sign extend val
        let sign = (val >> (self.bit_len - 1)) & 0x1;

        for i in self.bit_len..128 {
            val += sign << i;
        }

        val as i128
    }
}

impl TranscipheredInt<Unsigned> {
    /// Decrypt the contained integer using the given [`SecretOneTimePad`].
    pub fn decrypt(&self, otp: &SecretOneTimePad) -> u128 {
        self.decrypt_inner(otp)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        DEFAULT_128, KeylessEvaluation, PublicKey,
        fluent::{PackedInt32, PackedUInt32},
        generate_one_time_pad,
        test_utils::{get_encryption_128, get_secret_keys_128},
    };

    #[test]
    fn transcipher_signed() {
        let enc = get_encryption_128();
        let eval = KeylessEvaluation::new(&DEFAULT_128, &enc);
        let sk = get_secret_keys_128();
        let pk = PublicKey::generate(&DEFAULT_128, &sk);

        let val = PackedInt32::encrypt(-42i128, &enc, &pk);

        let (pub_otp, priv_otp) = generate_one_time_pad(&DEFAULT_128, &enc, &pk);

        let t = val.transcipher(&enc, &eval, &pub_otp);
        let t = t.decrypt(&enc, &sk);
        let actual = t.decrypt(&priv_otp);

        assert_eq!(actual, -42);
    }

    #[test]
    fn transcipher_unsigned() {
        let enc = get_encryption_128();
        let eval = KeylessEvaluation::new(&DEFAULT_128, &enc);
        let sk = get_secret_keys_128();
        let pk = PublicKey::generate(&DEFAULT_128, &sk);

        let val = PackedUInt32::encrypt(42, &enc, &pk);

        let (pub_otp, priv_otp) = generate_one_time_pad(&DEFAULT_128, &enc, &pk);

        let t = val.transcipher(&enc, &eval, &pub_otp);
        let t = t.decrypt(&enc, &sk);
        let actual = t.decrypt(&priv_otp);

        assert_eq!(actual, 42);
    }
}
