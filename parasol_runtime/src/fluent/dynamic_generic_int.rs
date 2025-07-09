use std::{marker::PhantomData, sync::Arc};

use parasol_concurrency::AtomicRefCell;
use serde::{Deserialize, Serialize};
use sunscreen_tfhe::entities::Polynomial;

use crate::{
    Encryption, Evaluation, L1GlweCiphertext, PublicKey, SecretKey,
    fluent::{CiphertextOps, DynamicGenericIntGraphNodes, FheCircuitCtx, PlaintextOps, Sign},
};

#[derive(Clone, Serialize, Deserialize)]
/// A dynamic generic integer stored in unpacked form. A dynamic generic integer encrypts its bits in
/// a few different ciphertexts of type `T` where the number of bits also represent the bit width
pub struct DynamicGenericInt<T: CiphertextOps, U: Sign> {
    /// The ciphertexts encrypting this dynamic generic integer's bits in least-to-most significant order.
    pub bits: Vec<Arc<AtomicRefCell<T>>>,
    _phantom: PhantomData<U>,
}

impl<T, U> DynamicGenericInt<T, U>
where
    T: CiphertextOps,
    U: Sign,
{
    /// Allocate a new [`DynamicGenericInt`] using trivial or precomputed (if T is [`L1GgswCiphertext`](crate::L1GgswCiphertext)) encryptions
    /// of zero.
    pub fn new(enc: &Encryption, n: usize) -> Self {
        Self {
            bits: (0..n)
                .map(|_| Arc::new(AtomicRefCell::new(T::allocate(enc))))
                .collect(),
            _phantom: PhantomData,
        }
    }

    /// Create a [`DynamicGenericInt`] from a previously encrypted set of type `T` ciphertexts.
    ///
    /// # Remarks
    /// `bits` are ordered from least to most significant.
    ///
    /// This performs a deep copy of the underlying data.
    pub fn from_bits_deep(bits: Vec<T>) -> Self {
        Self {
            bits: bits
                .into_iter()
                .map(|x| Arc::new(AtomicRefCell::new(x)))
                .collect(),
            _phantom: PhantomData,
        }
    }

    /// Create a [`DynamicGenericInt`] from The inner ref-counted set of `T` ciphertexts.
    ///
    /// # Remarks
    /// `bits` are ordered from least to most significant.
    ///
    /// This performs a shallow copy of the underlying data.
    pub fn from_bits_shallow(bits: Vec<Arc<AtomicRefCell<T>>>) -> Self {
        Self {
            bits,
            _phantom: PhantomData,
        }
    }

    /// Encrypts the given integer.
    ///
    /// # Panics
    /// If the given value is out of bounds.
    pub fn encrypt_secret(
        val: U::PlaintextType,
        enc: &Encryption,
        sk: &SecretKey,
        n: usize,
    ) -> Self {
        val.assert_in_bounds(n);

        Self {
            bits: val
                .to_bits(n)
                .map(|x| {
                    let ct = T::encrypt_secret(x, enc, sk);
                    Arc::new(AtomicRefCell::new(ct))
                })
                .collect(),
            _phantom: PhantomData,
        }
    }

    /// Decrypts this encrypted integer and returns the contained integer message.
    pub fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> U::PlaintextType {
        self.with_decryption_fn(|x| x.decrypt(enc, sk))
    }

    /// Add input nodes to the given [`FheCircuitCtx`].
    pub fn graph_inputs<'a>(
        &self,
        ctx: &'a FheCircuitCtx,
    ) -> DynamicGenericIntGraphNodes<'a, T, U> {
        DynamicGenericIntGraphNodes::from_nodes(
            self.bits
                .iter()
                .map(|b| ctx.circuit.borrow_mut().add_node(T::graph_input(b))),
            &ctx.allocator,
        )
    }

    /// Run a custom (e.g. threshold) decryption algorithm and return the result.
    pub fn with_decryption_fn<F>(&self, f: F) -> U::PlaintextType
    where
        F: Fn(&T) -> bool,
    {
        U::PlaintextType::from_bits(self.bits.iter().map(|x| f(&x.borrow())))
    }

    /// Create a trivial encryption of `val`.
    ///
    /// # Remarks
    /// If `T` is [`L1GgswCiphertext`](crate::L1GgswCiphertext), then the result
    /// will contain precomputed rather than trivial ciphertexts.
    ///
    /// # Panics
    /// If `val >= 2**n` or `val < -(2**n)`
    pub fn trivial(val: U::PlaintextType, enc: &Encryption, eval: &Evaluation, n: usize) -> Self {
        val.assert_in_bounds(n);

        Self {
            bits: val
                .to_bits(n)
                .map(|i| {
                    let ct = T::trivial_encryption(i, enc, eval);
                    Arc::new(AtomicRefCell::new(ct))
                })
                .collect(),
            _phantom: PhantomData,
        }
    }
}

impl<U> DynamicGenericInt<L1GlweCiphertext, U>
where
    U: Sign,
{
    /// Encrypt `val` using [`PublicKey`].
    ///
    /// # Remarks
    /// Requires the encryption parameters support RLWE encryption. [`crate::DEFAULT_128`]
    /// have this property.
    ///
    /// It's generally recommended to encrypt a [`crate::fluent::PackedDynamicGenericInt`]
    /// and unpack the result, as they're significantly smaller.
    pub fn encrypt(val: U::PlaintextType, enc: &Encryption, pk: &PublicKey, n: usize) -> Self {
        val.assert_in_bounds(n);

        let zero = Polynomial::<u64>::zero(enc.params.l1_poly_degree().0);
        let mut one = zero.clone();
        one.coeffs_mut()[0] = 1;

        Self {
            bits: val
                .to_bits(n)
                .map(|i| {
                    let msg = if i { &one } else { &zero };

                    let ct = enc.encrypt_rlwe_l1(msg, pk);
                    Arc::new(AtomicRefCell::new(ct))
                })
                .collect::<Vec<_>>(),
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Encryption, PublicKey,
        fluent::{Signed, Unsigned},
        test_utils::get_secret_keys_128,
    };

    #[test]
    fn can_public_key_encrypt_dynamic_generic_int() {
        let sk = get_secret_keys_128();
        let pk = PublicKey::generate_with_default_params(&sk);
        let enc = Encryption::default();

        let val = DynamicGenericInt::<L1GlweCiphertext, Unsigned>::encrypt(42, &enc, &pk, 16);

        assert_eq!(val.decrypt(&enc, &sk), 42);

        let val = DynamicGenericInt::<L1GlweCiphertext, Signed>::encrypt(-42, &enc, &pk, 16);

        assert_eq!(val.decrypt(&enc, &sk), -42);
    }
}
