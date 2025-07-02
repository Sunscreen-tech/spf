use std::{marker::PhantomData, mem::size_of, ops::Deref, sync::Arc};

use crate::{
    Encryption, Evaluation, KeylessEvaluation, L1GlweCiphertext, SecretKey,
    crypto::{PublicKey, PublicOneTimePad},
    fluent::{DynamicGenericInt, EncryptedRecryptedGenricInt, PackedDynamicGenericIntGraphNode},
    recrypt_one_time_pad,
    safe_bincode::GetSize,
};

use super::{CiphertextOps, FheCircuit, FheCircuitCtx, Muxable, PolynomialCiphertextOps};

use mux_circuits::MuxCircuit;
use parasol_concurrency::AtomicRefCell;
use petgraph::stable_graph::NodeIndex;
use serde::{Deserialize, Serialize};
use sunscreen_tfhe::entities::Polynomial;

/// Operations over plaintext integers used during encryption/decryption
pub trait PlaintextOps: Copy + PartialEq + std::fmt::Debug {
    /// Asserts theis value is in bounds for the given number of bits.
    fn assert_in_bounds(&self, bits: usize);

    /// Convert the given iterator over the value's bits, create this value.
    fn from_bits<I: Iterator<Item = bool>>(iter: I) -> Self;

    /// Iterate over the bits in this value (least to most significant).
    fn to_bits(&self, len: usize) -> impl Iterator<Item = bool>;
}

/// Trait for distinguishing unsigned and signed integer types
pub trait Sign {
    /// The plaintext type when encrypting/decrypting
    type PlaintextType: PlaintextOps;

    /// Compare circuit generation function for this sign
    fn gen_compare_circuit(max_len: usize, gt: bool, eq: bool) -> MuxCircuit;

    /// Multiplication function for this sign
    fn append_multiply<OutCt: Muxable>(
        uop_graph: &mut FheCircuit,
        a: &[NodeIndex],
        b: &[NodeIndex],
    ) -> (Vec<NodeIndex>, Vec<NodeIndex>);

    /// Resize configuration function for this sign
    /// Returned tuple includes min_len, extend_len, whether_to_extend_msb
    fn resize_config(old_size: usize, new_size: usize) -> (usize, usize, bool);
}

#[derive(Clone, Serialize, Deserialize)]
/// A generic integer with a constant size generic parameter, similar to [`DynamicGenericInt`]
/// and uses it as the internal representation
pub struct GenericInt<const N: usize, T: CiphertextOps, U: Sign> {
    inner: DynamicGenericInt<T, U>,
}

impl<const N: usize, T: CiphertextOps, U: Sign> Deref for GenericInt<N, T, U> {
    type Target = DynamicGenericInt<T, U>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<const N: usize, T: CiphertextOps, U: Sign> From<GenericInt<N, T, U>>
    for DynamicGenericInt<T, U>
{
    fn from(value: GenericInt<N, T, U>) -> DynamicGenericInt<T, U> {
        value.inner
    }
}

impl<const N: usize, T: CiphertextOps, U: Sign> From<DynamicGenericInt<T, U>>
    for GenericInt<N, T, U>
{
    fn from(value: DynamicGenericInt<T, U>) -> Self {
        assert_eq!(value.bits.len(), N);

        Self { inner: value }
    }
}

impl<const N: usize, T: CiphertextOps, U: Sign> GetSize for GenericInt<N, T, U> {
    fn get_size(params: &crate::Params) -> usize {
        N * T::get_size(params) + size_of::<u64>()
    }

    fn check_is_valid(&self, params: &crate::Params) -> crate::Result<()> {
        for b in &self.inner.bits {
            b.borrow().check_is_valid(params)?;
        }

        Ok(())
    }
}

impl<const N: usize, T, U> GenericInt<N, T, U>
where
    T: CiphertextOps,
    U: Sign,
{
    /// Allocate a new [`GenericInt`] using trivial or precomputed (if T is [`L1GgswCiphertext`](crate::L1GgswCiphertext)) encryptions
    /// of zero.
    pub fn new(enc: &Encryption) -> Self {
        Self {
            inner: DynamicGenericInt::new(enc, N),
        }
    }

    /// Create a [`GenericInt`] from the underlying bits
    pub fn from_bits_shallow(bits: Vec<Arc<AtomicRefCell<T>>>) -> Self {
        Self {
            inner: DynamicGenericInt::from_bits_shallow(bits),
        }
    }

    /// Encrypt the given integer
    pub fn encrypt_secret(val: U::PlaintextType, enc: &Encryption, sk: &SecretKey) -> Self {
        Self {
            inner: DynamicGenericInt::<_, U>::encrypt_secret(val, enc, sk, N),
        }
    }

    /// Decrypts the encrypted integer
    pub fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> U::PlaintextType {
        self.inner.decrypt(enc, sk)
    }

    /// Trivially encrypt the given integer
    pub fn trivial(val: U::PlaintextType, enc: &Encryption, eval: &Evaluation) -> Self {
        Self {
            inner: DynamicGenericInt::<_, U>::trivial(val, enc, eval, N),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
/// An `N`-bit integer encrypted and packed into a single ciphertext of type `T`. Note `T` must
/// allow polynomial messages (e.g. [`L1GlweCiphertext`]).
///
/// # Remarks
/// The plaintext coefficient corresponding to `x**n` contains the `n`-th bit of the integer ordered
/// from least to most significant. For example, the number `10 = 0b1010` would be stored as
/// `0x^0 + 1x^1 + 0x^2 + 1x^3`.
///
/// For integers greater than a few (e.g. 6) bits, packing integers reduces their size for
/// transmission over the wire.
///
/// Packed integers must be unpacked (with [`PackedDynamicGenericIntGraphNode::unpack`]) before you can perform
/// computation.
///
/// # Example
/// ```rust
/// # use parasol_runtime::{
/// #   test_utils::{get_encryption_128, get_public_key_128, get_secret_keys_128, make_uproc_128},
/// #   L0LweCiphertext, L1GlweCiphertext, DEFAULT_128, fluent::{FheCircuitCtx, PackedGenericInt, Unsigned}
/// # };
/// # let enc = get_encryption_128();
///
/// # let sk = get_secret_keys_128();
/// # let pk = get_public_key_128();
/// # let (uproc, fc) = make_uproc_128();
///
/// let val = PackedGenericInt::<16, L1GlweCiphertext, Unsigned>::encrypt(42, &enc, &pk);
///
/// let ctx = FheCircuitCtx::new();
///
/// let as_unpacked = val
///     .graph_input(&ctx)
///     .unpack(&ctx)
///     .collect_outputs(&ctx, &enc);
///
/// uproc
///     .lock()
///     .unwrap()
///     .run_graph_blocking(&ctx.circuit.borrow(), &fc);
///
/// assert_eq!(as_unpacked.decrypt(&enc, &sk), 42);
/// ```
pub struct PackedDynamicGenericInt<T, U>
where
    T: CiphertextOps + PolynomialCiphertextOps,
    U: Sign,
{
    pub(crate) bit_len: u32,
    pub(crate) ct: Arc<AtomicRefCell<T>>,
    pub(crate) _phantom: PhantomData<U>,
}

impl<T, U> From<(u32, T)> for PackedDynamicGenericInt<T, U>
where
    T: CiphertextOps + PolynomialCiphertextOps,
    U: Sign,
{
    fn from(value: (u32, T)) -> Self {
        Self {
            bit_len: value.0,
            ct: Arc::new(AtomicRefCell::new(value.1)),
            _phantom: PhantomData,
        }
    }
}

impl<T: CiphertextOps + PolynomialCiphertextOps, U: Sign> GetSize
    for PackedDynamicGenericInt<T, U>
{
    fn get_size(params: &crate::Params) -> usize {
        size_of::<u32>() + T::get_size(params)
    }

    fn check_is_valid(&self, params: &crate::Params) -> crate::Result<()> {
        self.ct.borrow().check_is_valid(params)
    }
}

impl<T, U> PackedDynamicGenericInt<T, U>
where
    T: CiphertextOps + PolynomialCiphertextOps,
    U: Sign,
{
    /// Encrypt and pack the given `val` into a single `T` ciphertext.
    /// See [`PackedDynamicGenericInt`] for more details on packing.
    pub fn encrypt(val: U::PlaintextType, enc: &Encryption, pk: &PublicKey, n: usize) -> Self {
        val.assert_in_bounds(n);

        let msg = Self::encode(val, enc, n);

        Self {
            bit_len: n as u32,
            ct: Arc::new(AtomicRefCell::new(T::encrypt(&msg, enc, pk))),
            _phantom: PhantomData,
        }
    }

    fn encode(val: U::PlaintextType, enc: &Encryption, n: usize) -> Polynomial<u64> {
        assert!(n < T::poly_degree(&enc.params).0);

        let coeffs = val
            .to_bits(n)
            .map(|x| x as u64)
            .chain(std::iter::repeat(0))
            .take(enc.params.l1_poly_degree().0)
            .collect::<Vec<_>>();

        Polynomial::<u64>::new(&coeffs)
    }

    /// Decrypt this packed encrypted dynamic generic integer.
    pub fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> U::PlaintextType {
        let n = self.bit_len as usize;

        assert!(n < T::poly_degree(&enc.params).0);

        let poly = <T as PolynomialCiphertextOps>::decrypt(&self.ct.borrow(), enc, sk);

        U::PlaintextType::from_bits(
            poly.coeffs()
                .iter()
                .map(|x| *x == 0x1)
                .take(self.bit_len as usize),
        )
    }

    /// Create an input node in the [`FheCircuitCtx`] graph.
    pub fn graph_input(&self, ctx: &FheCircuitCtx) -> PackedDynamicGenericIntGraphNode<T, U> {
        PackedDynamicGenericIntGraphNode {
            bit_len: self.bit_len,
            id: ctx.circuit.borrow_mut().add_node(T::graph_input(&self.ct)),
            _phantom: PhantomData,
        }
    }

    /// Trivially encrypt the given value as a [`PackedDynamicGenericInt`].
    pub fn trivial_encrypt(val: U::PlaintextType, enc: &Encryption, n: usize) -> Self {
        let msg = Self::encode(val, enc, n);

        Self {
            bit_len: n as u32,
            ct: Arc::new(AtomicRefCell::new(
                <T as PolynomialCiphertextOps>::trivial_encryption(&msg, enc),
            )),
            _phantom: PhantomData,
        }
    }

    /// Returns the inner ciphertext.
    pub fn inner(&self) -> T {
        self.ct.borrow().clone()
    }
}

impl<U: Sign> PackedDynamicGenericInt<L1GlweCiphertext, U> {
    /// Recrypts this integer under the given [`PublicOneTimePad`].
    pub fn recrypt(
        &self,
        enc: &Encryption,
        eval: &KeylessEvaluation,
        otp: &PublicOneTimePad,
    ) -> EncryptedRecryptedGenricInt<U> {
        let t = recrypt_one_time_pad(&self.ct.borrow(), otp, eval, enc);

        EncryptedRecryptedGenricInt::new(self.bit_len, t)
    }
}
