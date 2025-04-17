use std::{marker::PhantomData, mem::size_of, sync::Arc};

use crate::{
    Encryption, Evaluation, FheEdge, FheOp, L1GgswCiphertext, L1GlweCiphertext, L1LweCiphertext,
    SecretKey, crypto::PublicKey, safe_bincode::GetSize,
};

use super::{
    CiphertextOps, FheCircuit, FheCircuitCtx, Muxable, PolynomialCiphertextOps, bit::BitNode,
};

use bumpalo::Bump;
use mux_circuits::{
    MuxCircuit,
    add::ripple_carry_adder,
    and::make_and_circuit,
    comparisons::{compare_equal, compare_not_equal},
    sub::full_subtractor,
};
use parasol_concurrency::AtomicRefCell;
use petgraph::stable_graph::NodeIndex;
use serde::{Deserialize, Serialize};
use sunscreen_tfhe::entities::Polynomial;

/// Trait for distinguishing unsigned and signed integer types
pub trait Sign {
    /// Compare circuit generation function for this sign
    fn gen_compare_circuit(max_len: usize, gt: bool, eq: bool) -> MuxCircuit;

    /// Multiplication function for this sign
    fn append_multiply<OutCt: Muxable>(
        uop_graph: &mut FheCircuit,
        a: &[NodeIndex],
        b: &[NodeIndex],
    ) -> (Vec<NodeIndex>, Vec<NodeIndex>);

    /// Resize implementation function for this sign
    fn resize<T: CiphertextOps>(
        input: &[BitNode<T>],
        zero: &BitNode<T>,
        old_size: usize,
        new_size: usize,
    ) -> impl Iterator<Item = BitNode<T>>;
}

/// A collection of graph nodes resulting from FHE operations over generic integers (e.g. the
/// result of adding two 7-bit values).
///
/// # Remarks
/// This integer is in unpacked form, meaning each bit resides in a different ciphertext of type `T`.
pub struct GenericIntGraphNodes<'a, const N: usize, T: CiphertextOps, U: Sign> {
    /// The generic integer's [`BitNode`]s from least to most significant.
    pub bits: &'a [BitNode<T>],

    _phantom: PhantomData<U>,
}

impl<'a, const N: usize, T: CiphertextOps, U: Sign> GenericIntGraphNodes<'a, N, T, U> {
    pub(crate) fn from_nodes<I: Iterator<Item = NodeIndex>>(
        iter: I,
        bump: &'a Bump,
    ) -> GenericIntGraphNodes<'a, N, T, U> {
        let nodes: &mut [BitNode<T>] = bump.alloc_slice_fill_default(N);

        for (idx, bit_node) in iter.zip(nodes.iter_mut()) {
            bit_node.node = idx
        }

        Self {
            bits: nodes,
            _phantom: PhantomData,
        }
    }

    pub(super) fn from_bit_nodes<I: Iterator<Item = BitNode<T>>>(
        iter: I,
        bump: &'a Bump,
    ) -> GenericIntGraphNodes<'a, N, T, U> {
        let nodes: &mut [BitNode<T>] = bump.alloc_slice_fill_default(N);

        for (idx, bit_node) in iter.zip(nodes.iter_mut()) {
            *bit_node = idx
        }

        Self {
            bits: nodes,
            _phantom: PhantomData,
        }
    }

    /// Convert this [`GenericIntGraphNodes<T, W>`] to a [`GenericIntGraphNodes<V, W>`]. Usually, you'll use this
    /// to convert to [`L1GgswCiphertext`] so you can perform arithmetic computation over integers.
    pub fn convert<V: CiphertextOps>(
        &self,
        graph: &'a FheCircuitCtx,
    ) -> GenericIntGraphNodes<'a, N, V, U> {
        let iter = self.bits.iter().map(|x| x.convert(graph));

        GenericIntGraphNodes::from_bit_nodes(iter, &graph.allocator)
    }

    /// Add output nodes to the computation for each of this generic integer's bits.
    /// When the [`FheCircuitCtx`]'s DAG finishes computing, the returned [`GenericInt<N, T>`] will encrypt
    /// the result of this generic integer's DAG nodes.
    ///
    /// # Remarks
    /// The returned [`GenericInt`] has not yet been evaluated and will be a trivial zero until the
    /// computation completes. You should generally submit the computation using
    /// [`crate::UOpProcessor::run_graph_blocking`] before using the returned result.
    ///
    /// Ciphertexts internally use safeguards that will prevent data races, but you may incur
    /// a panic if you attempt to read the ciphertext while [`crate::UOpProcessor::spawn_graph`]
    /// is running.
    pub fn collect_outputs(&self, ctx: &FheCircuitCtx, enc: &Encryption) -> GenericInt<N, T, U> {
        let result = GenericInt::new(enc);

        for (prev, res) in self.bits.iter().zip(result.bits.iter()) {
            let mut circuit = ctx.circuit.borrow_mut();

            let output = circuit.add_node(T::graph_output(res));
            circuit.add_edge(prev.node, output, FheEdge::Unary);
        }

        result
    }

    /// Resize skeleton that uses the method provided by the sign
    pub fn resize<const M: usize>(
        &self,
        ctx: &'a FheCircuitCtx,
    ) -> GenericIntGraphNodes<'a, M, T, U> {
        GenericIntGraphNodes::from_bit_nodes(
            U::resize(self.bits, &BitNode::zero(ctx), N, M),
            &ctx.allocator,
        )
    }
}

impl<const N: usize, U: Sign> GenericIntGraphNodes<'_, N, L1GlweCiphertext, U> {
    /// Convert this unpacked generic integer to packed form.
    ///
    /// # Remarks
    /// This requires T be an [`L1GlweCiphertext`]. If required, use [`Self::convert`] to get into
    /// this form.
    pub fn pack(
        &self,
        ctx: &FheCircuitCtx,
        enc: &Encryption,
    ) -> PackedGenericIntGraphNode<N, L1GlweCiphertext, U> {
        assert!(N <= enc.params.l1_poly_degree().0);
        assert!(N > 0);

        let log_n = N.next_power_of_two().ilog2();

        // Multiply the i'th bit polynomial by x^1. When these resultant
        // polynomials are summed, the i'th bit will appear in the x^i
        // term.
        let shifted = self
            .bits
            .iter()
            .enumerate()
            .map(|(i, x)| {
                let mut circuit = ctx.circuit.borrow_mut();

                if i > 0 {
                    let rot = circuit.add_node(FheOp::MulXN(i));
                    circuit.add_edge(x.node, rot, FheEdge::Unary);

                    rot
                } else {
                    x.node
                }
            })
            .collect::<Vec<_>>();

        let mut reduction = shifted;

        // Perform a tree reduction to sum the shifted ciphertexts.
        for _ in 0..log_n {
            assert!(reduction.len() > 1);

            let next = reduction
                .chunks(2)
                .map(|x| {
                    if x.len() == 1 {
                        x[0]
                    } else {
                        let mut circuit = ctx.circuit.borrow_mut();

                        let add = circuit.add_node(FheOp::GlweAdd);
                        circuit.add_edge(x[0], add, FheEdge::Left);
                        circuit.add_edge(x[1], add, FheEdge::Right);

                        add
                    }
                })
                .collect::<Vec<_>>();

            reduction = next;
        }

        assert_eq!(reduction.len(), 1);

        PackedGenericIntGraphNode {
            id: reduction[0],
            _phantom: PhantomData,
        }
    }
}

impl<'a, const N: usize, V: Sign> GenericIntGraphNodes<'a, N, L1GgswCiphertext, V> {
    pub(crate) fn cmp<const M: usize, OutCt: Muxable>(
        &self,
        other: &GenericIntGraphNodes<M, L1GgswCiphertext, V>,
        ctx: &FheCircuitCtx,
        gt: bool,
        eq: bool,
    ) -> BitNode<OutCt> {
        let max_len = M.max(N);
        let mux_circuit = V::gen_compare_circuit(max_len, gt, eq);

        let zero = ctx.circuit.borrow_mut().add_node(FheOp::ZeroGgsw1);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .chain(self.bits.iter().skip(M).flat_map(|x| [x.node, zero]))
            .chain(other.bits.iter().skip(N).flat_map(|x| [zero, x.node]))
            .collect::<Vec<_>>();

        let cmp_result = ctx.circuit.borrow_mut().insert_mux_circuit(
            &mux_circuit,
            &interleaved,
            OutCt::MUX_MODE,
        );

        BitNode {
            node: cmp_result[0],
            _phantom: PhantomData,
        }
    }

    /// Compute `self == other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn eq<const M: usize, OutCt: Muxable>(
        &self,
        other: &GenericIntGraphNodes<M, L1GgswCiphertext, V>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        let max_len = M.max(N);
        let mux_circuit = compare_equal(max_len);

        let zero = ctx.circuit.borrow_mut().add_node(FheOp::ZeroGgsw1);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .chain(self.bits.iter().skip(M).flat_map(|x| [x.node, zero]))
            .chain(other.bits.iter().skip(N).flat_map(|x| [zero, x.node]))
            .collect::<Vec<_>>();

        let eq = ctx.circuit.borrow_mut().insert_mux_circuit(
            &mux_circuit,
            &interleaved,
            OutCt::MUX_MODE,
        );

        BitNode {
            node: eq[0],
            _phantom: PhantomData,
        }
    }

    /// Compute `self != other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn neq<const M: usize, OutCt: Muxable>(
        &self,
        other: &GenericIntGraphNodes<M, L1GgswCiphertext, V>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        let max_len = M.max(N);
        let mux_circuit = compare_not_equal(max_len);

        let zero = ctx.circuit.borrow_mut().add_node(FheOp::ZeroGgsw1);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .chain(self.bits.iter().skip(M).flat_map(|x| [x.node, zero]))
            .chain(other.bits.iter().skip(N).flat_map(|x| [zero, x.node]))
            .collect::<Vec<_>>();

        let eq = ctx.circuit.borrow_mut().insert_mux_circuit(
            &mux_circuit,
            &interleaved,
            OutCt::MUX_MODE,
        );

        BitNode {
            node: eq[0],
            _phantom: PhantomData,
        }
    }

    /// Compute `self > other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn gt<const M: usize, OutCt: Muxable>(
        &self,
        other: &GenericIntGraphNodes<M, L1GgswCiphertext, V>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        self.cmp(other, ctx, true, false)
    }

    /// Compute `self >= other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn ge<const M: usize, OutCt: Muxable>(
        &self,
        other: &GenericIntGraphNodes<M, L1GgswCiphertext, V>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        self.cmp(other, ctx, true, true)
    }

    /// Compute `self < other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn lt<const M: usize, OutCt: Muxable>(
        &self,
        other: &GenericIntGraphNodes<M, L1GgswCiphertext, V>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        self.cmp(other, ctx, false, false)
    }

    /// Compute `self <= other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn le<const M: usize, OutCt: Muxable>(
        &self,
        other: &GenericIntGraphNodes<M, L1GgswCiphertext, V>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        self.cmp(other, ctx, false, true)
    }

    /// Compute `self - other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn sub<OutCt: Muxable>(
        &self,
        other: &Self,
        ctx: &'a FheCircuitCtx,
    ) -> GenericIntGraphNodes<'a, N, OutCt, V> {
        let mux_circuit = full_subtractor(N, false);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .collect::<Vec<_>>();

        GenericIntGraphNodes::from_nodes(
            ctx.circuit
                .borrow_mut()
                .insert_mux_circuit(&mux_circuit, &interleaved, OutCt::MUX_MODE)
                .iter()
                .copied()
                .take(N),
            &ctx.allocator,
        )
    }

    /// Compute `self & other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn and<OutCt: Muxable>(
        &self,
        other: &Self,
        ctx: &'a FheCircuitCtx,
    ) -> GenericIntGraphNodes<'a, N, OutCt, V> {
        let mux_circuit = make_and_circuit(N as u16);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .collect::<Vec<_>>();

        GenericIntGraphNodes::from_nodes(
            ctx.circuit
                .borrow_mut()
                .insert_mux_circuit(&mux_circuit, &interleaved, OutCt::MUX_MODE)
                .iter()
                .copied()
                .take(N),
            &ctx.allocator,
        )
    }

    /// Compute `self + other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn add<OutCt: Muxable>(
        &self,
        other: &Self,
        ctx: &'a FheCircuitCtx,
    ) -> GenericIntGraphNodes<'a, N, OutCt, V> {
        let mux_circuit = ripple_carry_adder(N, N, false);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .collect::<Vec<_>>();

        GenericIntGraphNodes::from_nodes(
            ctx.circuit
                .borrow_mut()
                .insert_mux_circuit(&mux_circuit, &interleaved, OutCt::MUX_MODE)
                .iter()
                .copied()
                .take(N),
            &ctx.allocator,
        )
    }

    /// Compute `self * other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn mul<OutCt: Muxable>(
        &self,
        other: &Self,
        ctx: &'a FheCircuitCtx,
    ) -> GenericIntGraphNodes<'a, N, OutCt, V> {
        let a = self.bits.iter().map(|x| x.node).collect::<Vec<_>>();

        let b = other.bits.iter().map(|x| x.node).collect::<Vec<_>>();

        let (lo, _hi) = V::append_multiply::<OutCt>(&mut ctx.circuit.borrow_mut(), &a, &b);

        // TODO: prune the high bits somehow?

        GenericIntGraphNodes::from_nodes(lo.into_iter(), &ctx.allocator)
    }
}

/// A graph node that represents a generic integer in packed form. See [`PackedGenericInt`] for a
/// description of packing.
pub struct PackedGenericIntGraphNode<
    const N: usize,
    T: CiphertextOps + PolynomialCiphertextOps,
    U: Sign,
> {
    id: NodeIndex,
    _phantom: PhantomData<(T, U)>,
}

impl<const N: usize, V: Sign> PackedGenericIntGraphNode<N, L1GlweCiphertext, V> {
    /// Convert this integer into unpacked form, where each bit appears in a different ciphertext.
    pub fn unpack<'a>(
        &self,
        ctx: &'a FheCircuitCtx,
    ) -> GenericIntGraphNodes<'a, N, L1LweCiphertext, V> {
        let nodes = (0..N).map(|i| {
            let mut circuit = ctx.circuit.borrow_mut();

            let se = circuit.add_node(FheOp::SampleExtract(i));
            circuit.add_edge(self.id, se, FheEdge::Unary);

            se
        });

        GenericIntGraphNodes::from_nodes(nodes, &ctx.allocator)
    }
}

impl<const N: usize, T: CiphertextOps + PolynomialCiphertextOps, U: Sign>
    PackedGenericIntGraphNode<N, T, U>
{
    /// Create an output node in the graph and return the ciphertext.
    ///
    /// # Remarks
    /// The returned [`PackedGenericInt`] has not yet been evaluated and will be a trivial zero until the
    /// computation completes. You should generally submit the computation using
    /// [`crate::UOpProcessor::run_graph_blocking`] before using the returned result.
    ///
    /// Ciphertexts internally use safeguards that will prevent data races, but you may incur
    /// a panic if you attempt to read the ciphertext while [`crate::UOpProcessor::spawn_graph`]
    /// is running.
    pub fn collect_output(
        &self,
        ctx: &FheCircuitCtx,
        enc: &Encryption,
    ) -> PackedGenericInt<N, T, U> {
        let result = Arc::new(AtomicRefCell::new(T::allocate(enc)));

        let mut circuit = ctx.circuit.borrow_mut();

        let out_node = circuit.add_node(T::graph_output(&result));
        circuit.add_edge(self.id, out_node, FheEdge::Unary);

        PackedGenericInt {
            ct: result,
            _phantom: PhantomData,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
/// A generic integer store in unpacked form. An `N`-bit generic integer encrypts its bits in
/// `N` different ciphertexts of type `T`.
pub struct GenericInt<const N: usize, T: CiphertextOps, U: Sign> {
    /// The ciphertexts encrypting this generic integer's bits in least-to-most significant order.
    pub bits: Vec<Arc<AtomicRefCell<T>>>,
    _phantom: PhantomData<U>,
}

impl<const N: usize, T: CiphertextOps, U: Sign> GetSize for GenericInt<N, T, U> {
    fn get_size(params: &crate::Params) -> usize {
        N * T::get_size(params) + size_of::<u64>()
    }

    fn check_is_valid(&self, params: &crate::Params) -> crate::Result<()> {
        for b in &self.bits {
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
    /// Allocate a new GenericInt using trivial or precomputed (if T is [`L1GgswCiphertext`]) encryptions
    /// of zero.
    pub fn new(enc: &Encryption) -> Self {
        Self {
            bits: (0..N)
                .map(|_| Arc::new(AtomicRefCell::new(T::allocate(enc))))
                .collect(),
            _phantom: PhantomData,
        }
    }

    /// Create a [`GenericInt`] from a previously encrypted set of type `T` ciphertexts.
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

    /// Create a [`GenericInt`] from The inner ref-counted set of `T` ciphertexts.
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
    /// If `val > 2^N`
    pub fn encrypt_secret(val: u64, enc: &Encryption, sk: &SecretKey) -> Self {
        if val > 0x1 << N {
            panic!("Out of bounds");
        }

        Self {
            bits: (0..N)
                .map(|i| {
                    let ct = T::encrypt_secret((val >> i) & 0x1 == 0x1, enc, sk);
                    Arc::new(AtomicRefCell::new(ct))
                })
                .collect(),
            _phantom: PhantomData,
        }
    }

    /// Decrypts this encrypted integer and returns the contained GenericInt message.
    pub fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> u64 {
        self.with_decryption_fn(|x| x.decrypt(enc, sk))
    }

    /// Add input nodes to the given [`FheCircuitCtx`].
    pub fn graph_inputs<'a>(&self, ctx: &'a FheCircuitCtx) -> GenericIntGraphNodes<'a, N, T, U> {
        GenericIntGraphNodes::from_nodes(
            self.bits
                .iter()
                .map(|b| ctx.circuit.borrow_mut().add_node(T::graph_input(b))),
            &ctx.allocator,
        )
    }

    /// Run a custom (e.g. threshold) decryption algorithm and return the result.
    pub fn with_decryption_fn<F>(&self, f: F) -> u64
    where
        F: Fn(&T) -> bool,
    {
        self.bits.iter().enumerate().fold(0u64, |s, (i, x)| {
            let x = AtomicRefCell::borrow(x);

            s + ((f(&x) as u64) << i)
        })
    }

    /// Create a trivial encryption of `val`.
    ///
    /// # Remarks
    /// If `T` is [`L1GgswCiphertext`], then the result will contain precomputed
    /// rather than trivial ciphertexts.
    pub fn trivial(val: u64, enc: &Encryption, eval: &Evaluation) -> Self {
        if val > 0x1 << N {
            panic!("Out of bounds");
        }

        Self {
            bits: (0..N)
                .map(|i| {
                    let ct = T::trivial_encryption((val >> i) & 0x1 == 0x1, enc, eval);
                    Arc::new(AtomicRefCell::new(ct))
                })
                .collect(),
            _phantom: PhantomData,
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
/// Packed integers must be unpacked (with [`PackedGenericIntGraphNode::unpack`]) before you can perform
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
pub struct PackedGenericInt<const N: usize, T, U>
where
    T: CiphertextOps + PolynomialCiphertextOps,
    U: Sign,
{
    ct: Arc<AtomicRefCell<T>>,
    _phantom: PhantomData<U>,
}

impl<const N: usize, T, U> From<T> for PackedGenericInt<N, T, U>
where
    T: CiphertextOps + PolynomialCiphertextOps,
    U: Sign,
{
    fn from(value: T) -> Self {
        Self {
            ct: Arc::new(AtomicRefCell::new(value)),
            _phantom: PhantomData,
        }
    }
}

impl<const N: usize, T: CiphertextOps + PolynomialCiphertextOps, U: Sign> GetSize
    for PackedGenericInt<N, T, U>
{
    fn get_size(params: &crate::Params) -> usize {
        T::get_size(params)
    }

    fn check_is_valid(&self, params: &crate::Params) -> crate::Result<()> {
        self.ct.borrow().check_is_valid(params)
    }
}

impl<const N: usize, T, U> PackedGenericInt<N, T, U>
where
    T: CiphertextOps + PolynomialCiphertextOps,
    U: Sign,
{
    /// Encrypt and pack the given `val` into a single `T` ciphertext.
    /// See [`PackedGenericInt`] for more details on packing.
    pub fn encrypt(val: u64, enc: &Encryption, pk: &PublicKey) -> Self {
        let msg = Self::encode(val, enc);

        Self {
            ct: Arc::new(AtomicRefCell::new(T::encrypt(&msg, enc, pk))),
            _phantom: PhantomData,
        }
    }

    fn encode(val: u64, enc: &Encryption) -> Polynomial<u64> {
        assert!(val < 0x1 << N);
        assert!(N < T::poly_degree(&enc.params).0);

        let mut msg = Polynomial::<u64>::zero(T::poly_degree(&enc.params).0);

        for i in 0..N {
            msg.coeffs_mut()[i] = (val >> i) & 0x1;
        }

        msg
    }

    /// Decrypt this packed encrypted generic integer.
    pub fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> u64 {
        assert!(N < T::poly_degree(&enc.params).0);
        let mut val = 0;

        let poly = <T as PolynomialCiphertextOps>::decrypt(&self.ct.borrow(), enc, sk);

        for i in 0..N {
            val += poly.coeffs()[i] << i;
        }

        val
    }

    /// Create input nodes in the [`FheCircuitCtx`] graph.
    pub fn graph_input(&self, ctx: &FheCircuitCtx) -> PackedGenericIntGraphNode<N, T, U> {
        PackedGenericIntGraphNode {
            id: ctx.circuit.borrow_mut().add_node(T::graph_input(&self.ct)),
            _phantom: PhantomData,
        }
    }

    /// Trivially encrypt the given value as a [`PackedGenericInt`].
    pub fn trivial_encrypt(val: u64, enc: &Encryption) -> Self {
        let msg = Self::encode(val, enc);

        Self {
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
