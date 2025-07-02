use std::ops::Deref;

use serde::{Deserialize, Serialize};

use crate::{
    Encryption, PublicKey, SecretKey,
    fluent::{CiphertextOps, PackedDynamicGenericInt, PolynomialCiphertextOps, Sign},
    safe_bincode::GetSize,
};

#[derive(Clone, Serialize, Deserialize)]
/// A generic integer in the packed form with a constant size generic parameter, similar to [`PackedDynamicGenericInt`]
/// and uses it as the internal representation
pub struct PackedGenericInt<const N: usize, T, U>
where
    T: CiphertextOps + PolynomialCiphertextOps,
    U: Sign,
{
    inner: PackedDynamicGenericInt<T, U>,
}

impl<const N: usize, T, U> Deref for PackedGenericInt<N, T, U>
where
    T: CiphertextOps + PolynomialCiphertextOps,
    U: Sign,
{
    type Target = PackedDynamicGenericInt<T, U>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<const N: usize, T, U> From<PackedGenericInt<N, T, U>> for PackedDynamicGenericInt<T, U>
where
    T: CiphertextOps + PolynomialCiphertextOps,
    U: Sign,
{
    fn from(value: PackedGenericInt<N, T, U>) -> PackedDynamicGenericInt<T, U> {
        value.inner
    }
}

impl<const N: usize, T, U> From<PackedDynamicGenericInt<T, U>> for PackedGenericInt<N, T, U>
where
    T: CiphertextOps + PolynomialCiphertextOps,
    U: Sign,
{
    fn from(value: PackedDynamicGenericInt<T, U>) -> Self {
        assert_eq!(value.bit_len as usize, N);

        Self { inner: value }
    }
}

impl<const N: usize, T: CiphertextOps + PolynomialCiphertextOps, U: Sign> GetSize
    for PackedGenericInt<N, T, U>
{
    fn get_size(params: &crate::Params) -> usize {
        size_of::<u32>() + T::get_size(params)
    }

    fn check_is_valid(&self, params: &crate::Params) -> crate::Result<()> {
        self.inner.ct.borrow().check_is_valid(params)
    }
}

impl<const N: usize, T, U> PackedGenericInt<N, T, U>
where
    T: CiphertextOps + PolynomialCiphertextOps,
    U: Sign,
{
    /// Encrypt the given integer
    pub fn encrypt(val: U::PlaintextType, enc: &Encryption, pk: &PublicKey) -> Self {
        Self {
            inner: PackedDynamicGenericInt::encrypt(val, enc, pk, N),
        }
    }

    /// Trivially encrypt the given integer
    pub fn trivial_encrypt(val: U::PlaintextType, enc: &Encryption) -> Self {
        Self {
            inner: PackedDynamicGenericInt::trivial_encrypt(val, enc, N),
        }
    }

    /// Decrypts the given integer.
    pub fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> U::PlaintextType {
        self.inner.decrypt(enc, sk)
    }
}
