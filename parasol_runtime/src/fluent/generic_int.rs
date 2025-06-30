use std::{marker::PhantomData, mem::size_of, ops::Deref, sync::Arc};

use crate::{
    Encryption, Evaluation, FheEdge, FheOp, L1GgswCiphertext, L1GlweCiphertext, L1LweCiphertext,
    SecretKey, crypto::PublicKey, prune, safe_bincode::GetSize,
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

    /// Resize configuration function for this sign
    /// Returned tuple includes min_len, extend_len, whether_to_extend_msb
    fn resize_config(old_size: usize, new_size: usize) -> (usize, usize, bool);
}

/// A collection of graph nodes resulting from FHE operations over dynamic generic integers (e.g. the
/// result of adding two 7-bit values).
///
/// # Remarks
/// This integer is in unpacked form, meaning each bit resides in a different ciphertext of type `T`.
pub struct DynamicGenericIntGraphNodes<'a, T: CiphertextOps, U: Sign> {
    /// The dynamic generic integer's [`BitNode`]s from least to most significant.
    pub bits: &'a [BitNode<T>],

    _phantom: PhantomData<U>,
}

impl<'a, T: CiphertextOps, U: Sign> DynamicGenericIntGraphNodes<'a, T, U> {
    pub(crate) fn from_nodes<I: ExactSizeIterator<Item = NodeIndex>>(
        iter: I,
        bump: &'a Bump,
    ) -> DynamicGenericIntGraphNodes<'a, T, U> {
        let nodes: &mut [BitNode<T>] = bump.alloc_slice_fill_default(iter.len());

        for (idx, bit_node) in iter.zip(nodes.iter_mut()) {
            bit_node.node = idx
        }

        Self {
            bits: nodes,
            _phantom: PhantomData,
        }
    }

    pub(super) fn from_bit_nodes<I: ExactSizeIterator<Item = BitNode<T>>>(
        iter: I,
        bump: &'a Bump,
    ) -> DynamicGenericIntGraphNodes<'a, T, U> {
        let nodes: &mut [BitNode<T>] = bump.alloc_slice_fill_default(iter.len());

        for (idx, bit_node) in iter.zip(nodes.iter_mut()) {
            *bit_node = idx
        }

        Self {
            bits: nodes,
            _phantom: PhantomData,
        }
    }

    /// Convert this [`DynamicGenericIntGraphNodes<T, U>`] to a [`DynamicGenericIntGraphNodes<V, U>`]. Usually, you'll use this
    /// to convert to [`L1GgswCiphertext`] so you can perform arithmetic computation over integers.
    pub fn convert<V: CiphertextOps>(
        &self,
        graph: &'a FheCircuitCtx,
    ) -> DynamicGenericIntGraphNodes<'a, V, U> {
        let iter = self.bits.iter().map(|x| x.convert(graph));

        DynamicGenericIntGraphNodes::from_bit_nodes(iter, &graph.allocator)
    }

    /// Add output nodes to the computation for each of this dynamic generic integer's bits.
    /// When the [`FheCircuitCtx`]'s DAG finishes computing, the returned [`DynamicGenericInt<T, U>`] will encrypt
    /// the result of this dynamic generic integer's DAG nodes.
    ///
    /// # Remarks
    /// The returned [`DynamicGenericInt`] has not yet been evaluated and will be a trivial zero until the
    /// computation completes. You should generally submit the computation using
    /// [`crate::CircuitProcessor::run_graph_blocking`] before using the returned result.
    ///
    /// Ciphertexts internally use safeguards that will prevent data races, but you may incur
    /// a panic if you attempt to read the ciphertext while [`crate::CircuitProcessor::spawn_graph`]
    /// is running.
    pub fn collect_outputs(
        &self,
        ctx: &FheCircuitCtx,
        enc: &Encryption,
    ) -> DynamicGenericInt<T, U> {
        let result = DynamicGenericInt::new(enc, self.bits.len());

        for (prev, res) in self.bits.iter().zip(result.bits.iter()) {
            let mut circuit = ctx.circuit.borrow_mut();

            let output = circuit.add_node(T::graph_output(res));
            circuit.add_edge(prev.node, output, FheEdge::Unary);
        }

        result
    }

    /// Resize skeleton that uses the method provided by the sign
    pub fn resize(
        &self,
        ctx: &'a FheCircuitCtx,
        new_size: usize,
    ) -> DynamicGenericIntGraphNodes<'a, T, U> {
        let (min_len, extend, use_msb) = U::resize_config(self.bits.len(), new_size);

        let input = self.bits;

        let extend_bit = if use_msb {
            input.last().unwrap()
        } else {
            &BitNode::zero(ctx)
        };

        let iter = input
            .iter()
            .copied()
            .take(min_len)
            .chain((0..extend).map(|_| extend_bit.to_owned()))
            .collect::<Vec<_>>()
            .into_iter();

        DynamicGenericIntGraphNodes::from_bit_nodes(iter, &ctx.allocator)
    }
}

impl<U: Sign> DynamicGenericIntGraphNodes<'_, L1GlweCiphertext, U> {
    /// Convert this unpacked dynamic generic integer to packed form.
    ///
    /// # Remarks
    /// This requires T be an [`L1GlweCiphertext`]. If required, use [`Self::convert`] to get into
    /// this form.
    pub fn pack(
        &self,
        ctx: &FheCircuitCtx,
        enc: &Encryption,
    ) -> PackedDynamicGenericIntGraphNode<L1GlweCiphertext, U> {
        let n = self.bits.len();

        assert!(n <= enc.params.l1_poly_degree().0);
        assert!(n > 0);

        let log_n = n.next_power_of_two().ilog2();

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

        PackedDynamicGenericIntGraphNode {
            bit_len: n as u32,
            id: reduction[0],
            _phantom: PhantomData,
        }
    }
}

impl<'a, V: Sign> DynamicGenericIntGraphNodes<'a, L1GgswCiphertext, V> {
    pub(crate) fn cmp<OutCt: Muxable>(
        &self,
        other: &DynamicGenericIntGraphNodes<L1GgswCiphertext, V>,
        ctx: &FheCircuitCtx,
        gt: bool,
        eq: bool,
    ) -> BitNode<OutCt> {
        let m = other.bits.len();
        let n = self.bits.len();

        let max_len = m.max(n);
        let mux_circuit = V::gen_compare_circuit(max_len, gt, eq);

        let zero = ctx.circuit.borrow_mut().add_node(FheOp::ZeroGgsw1);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .chain(self.bits.iter().skip(m).flat_map(|x| [x.node, zero]))
            .chain(other.bits.iter().skip(n).flat_map(|x| [zero, x.node]))
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
    pub fn eq<OutCt: Muxable>(
        &self,
        other: &DynamicGenericIntGraphNodes<L1GgswCiphertext, V>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        let m = other.bits.len();
        let n = self.bits.len();

        let max_len = m.max(n);
        let mux_circuit = compare_equal(max_len);

        let zero = ctx.circuit.borrow_mut().add_node(FheOp::ZeroGgsw1);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .chain(self.bits.iter().skip(m).flat_map(|x| [x.node, zero]))
            .chain(other.bits.iter().skip(n).flat_map(|x| [zero, x.node]))
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
    pub fn neq<OutCt: Muxable>(
        &self,
        other: &DynamicGenericIntGraphNodes<L1GgswCiphertext, V>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        let m = other.bits.len();
        let n = self.bits.len();

        let max_len = m.max(n);
        let mux_circuit = compare_not_equal(max_len);

        let zero = ctx.circuit.borrow_mut().add_node(FheOp::ZeroGgsw1);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .chain(self.bits.iter().skip(m).flat_map(|x| [x.node, zero]))
            .chain(other.bits.iter().skip(n).flat_map(|x| [zero, x.node]))
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
    pub fn gt<OutCt: Muxable>(
        &self,
        other: &DynamicGenericIntGraphNodes<L1GgswCiphertext, V>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        self.cmp(other, ctx, true, false)
    }

    /// Compute `self >= other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn ge<OutCt: Muxable>(
        &self,
        other: &DynamicGenericIntGraphNodes<L1GgswCiphertext, V>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        self.cmp(other, ctx, true, true)
    }

    /// Compute `self < other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn lt<OutCt: Muxable>(
        &self,
        other: &DynamicGenericIntGraphNodes<L1GgswCiphertext, V>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        self.cmp(other, ctx, false, false)
    }

    /// Compute `self <= other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn le<OutCt: Muxable>(
        &self,
        other: &DynamicGenericIntGraphNodes<L1GgswCiphertext, V>,
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
    ) -> DynamicGenericIntGraphNodes<'a, OutCt, V> {
        let n = self.bits.len();

        let mux_circuit = full_subtractor(n, false);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .collect::<Vec<_>>();

        DynamicGenericIntGraphNodes::from_nodes(
            ctx.circuit
                .borrow_mut()
                .insert_mux_circuit(&mux_circuit, &interleaved, OutCt::MUX_MODE)
                .iter()
                .copied()
                .take(n),
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
    ) -> DynamicGenericIntGraphNodes<'a, OutCt, V> {
        let n = self.bits.len();

        let mux_circuit = make_and_circuit(n as u16);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .collect::<Vec<_>>();

        DynamicGenericIntGraphNodes::from_nodes(
            ctx.circuit
                .borrow_mut()
                .insert_mux_circuit(&mux_circuit, &interleaved, OutCt::MUX_MODE)
                .iter()
                .copied()
                .take(n),
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
    ) -> DynamicGenericIntGraphNodes<'a, OutCt, V> {
        let n = self.bits.len();

        let mux_circuit = ripple_carry_adder(n, n, false);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .collect::<Vec<_>>();

        DynamicGenericIntGraphNodes::from_nodes(
            ctx.circuit
                .borrow_mut()
                .insert_mux_circuit(&mux_circuit, &interleaved, OutCt::MUX_MODE)
                .iter()
                .copied()
                .take(n),
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
    ) -> DynamicGenericIntGraphNodes<'a, OutCt, V> {
        let a = self.bits.iter().map(|x| x.node).collect::<Vec<_>>();

        let b = other.bits.iter().map(|x| x.node).collect::<Vec<_>>();

        let mut circuit_mut = ctx.circuit.borrow_mut();

        // TODO: introduce a mul_lo so we don't have to do this pruning in the first place.
        let existing_outputs = circuit_mut
            .node_indices()
            .filter(|x| {
                let node_type = matches!(
                    circuit_mut.node_weight(*x).unwrap(),
                    FheOp::OutputGgsw1(_)
                        | FheOp::OutputGlev1(_)
                        | FheOp::OutputGlwe1(_)
                        | FheOp::OutputLwe0(_)
                        | FheOp::OutputLwe1(_)
                );

                node_type
                    && circuit_mut
                        .neighbors_directed(*x, petgraph::Direction::Outgoing)
                        .count()
                        == 0
            })
            .collect::<Vec<_>>();

        let (lo, _hi) = V::append_multiply::<OutCt>(&mut circuit_mut, &a, &b);

        let to_keep = [lo.clone(), existing_outputs].concat();

        let (pruned, rename) = prune(&circuit_mut, &to_keep);
        circuit_mut.graph = pruned;

        let lo = lo.into_iter().map(|x| *rename.get(&x).unwrap());

        DynamicGenericIntGraphNodes::from_nodes(lo, &ctx.allocator)
    }
}

/// A collection of graph nodes with a constant size generic parameter, similar to [`DynamicGenericIntGraphNodes`]
/// and uses it as the internal representation
pub struct GenericIntGraphNodes<'a, const N: usize, T: CiphertextOps, U: Sign> {
    inner: DynamicGenericIntGraphNodes<'a, T, U>,
}

impl<'a, const N: usize, T: CiphertextOps, U: Sign> Deref for GenericIntGraphNodes<'a, N, T, U> {
    type Target = DynamicGenericIntGraphNodes<'a, T, U>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, const N: usize, T: CiphertextOps, U: Sign> From<GenericIntGraphNodes<'a, N, T, U>>
    for DynamicGenericIntGraphNodes<'a, T, U>
{
    fn from(value: GenericIntGraphNodes<'a, N, T, U>) -> DynamicGenericIntGraphNodes<'a, T, U> {
        value.inner
    }
}

impl<'a, const N: usize, T: CiphertextOps, U: Sign> From<DynamicGenericIntGraphNodes<'a, T, U>>
    for GenericIntGraphNodes<'a, N, T, U>
{
    fn from(value: DynamicGenericIntGraphNodes<'a, T, U>) -> Self {
        assert_eq!(value.bits.len(), N);

        Self { inner: value }
    }
}

impl<'a, const N: usize, T: CiphertextOps, U: Sign> GenericIntGraphNodes<'a, N, T, U> {
    pub(crate) fn from_nodes<I: ExactSizeIterator<Item = NodeIndex>>(
        iter: I,
        bump: &'a Bump,
    ) -> GenericIntGraphNodes<'a, N, T, U> {
        assert_eq!(iter.len(), N);

        Self {
            inner: DynamicGenericIntGraphNodes::from_nodes(iter, bump),
        }
    }
}
/// A graph node that represents a dynamic generic integer in packed form. See [`PackedDynamicGenericInt`] for a
/// description of packing.
pub struct PackedDynamicGenericIntGraphNode<T: CiphertextOps + PolynomialCiphertextOps, U: Sign> {
    bit_len: u32,
    id: NodeIndex,
    _phantom: PhantomData<(T, U)>,
}

impl<V: Sign> PackedDynamicGenericIntGraphNode<L1GlweCiphertext, V> {
    /// Convert this integer node into unpacked form, where each bit appears in a different ciphertext.
    pub fn unpack<'a>(
        &self,
        ctx: &'a FheCircuitCtx,
    ) -> DynamicGenericIntGraphNodes<'a, L1LweCiphertext, V> {
        let nodes = (0..self.bit_len as usize).map(|i| {
            let mut circuit = ctx.circuit.borrow_mut();

            let se = circuit.add_node(FheOp::SampleExtract(i));
            circuit.add_edge(self.id, se, FheEdge::Unary);

            se
        });

        DynamicGenericIntGraphNodes::from_nodes(nodes, &ctx.allocator)
    }
}

impl<T: CiphertextOps + PolynomialCiphertextOps, U: Sign> PackedDynamicGenericIntGraphNode<T, U> {
    /// Create an output node in the graph and return the ciphertext.
    ///
    /// # Remarks
    /// The returned [`PackedDynamicGenericInt`] has not yet been evaluated and will be a trivial zero until the
    /// computation completes. You should generally submit the computation using
    /// [`crate::CircuitProcessor::run_graph_blocking`] before using the returned result.
    ///
    /// Ciphertexts internally use safeguards that will prevent data races, but you may incur
    /// a panic if you attempt to read the ciphertext while [`crate::CircuitProcessor::spawn_graph`]
    /// is running.
    pub fn collect_output(
        &self,
        ctx: &FheCircuitCtx,
        enc: &Encryption,
    ) -> PackedDynamicGenericInt<T, U> {
        let result = Arc::new(AtomicRefCell::new(T::allocate(enc)));

        let mut circuit = ctx.circuit.borrow_mut();

        let out_node = circuit.add_node(T::graph_output(&result));
        circuit.add_edge(self.id, out_node, FheEdge::Unary);

        PackedDynamicGenericInt {
            bit_len: self.bit_len,
            ct: result,
            _phantom: PhantomData,
        }
    }
}

/// FIXME
pub struct PackedGenericIntGraphNode<
    const N: usize,
    T: CiphertextOps + PolynomialCiphertextOps,
    U: Sign,
> {
    inner: PackedDynamicGenericIntGraphNode<T, U>,
}

impl<const N: usize, T: CiphertextOps + PolynomialCiphertextOps, U: Sign> Deref
    for PackedGenericIntGraphNode<N, T, U>
{
    type Target = PackedDynamicGenericIntGraphNode<T, U>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<const N: usize, T: CiphertextOps + PolynomialCiphertextOps, U: Sign>
    From<PackedGenericIntGraphNode<N, T, U>> for PackedDynamicGenericIntGraphNode<T, U>
{
    fn from(value: PackedGenericIntGraphNode<N, T, U>) -> PackedDynamicGenericIntGraphNode<T, U> {
        value.inner
    }
}

impl<const N: usize, T: CiphertextOps + PolynomialCiphertextOps, U: Sign>
    From<PackedDynamicGenericIntGraphNode<T, U>> for PackedGenericIntGraphNode<N, T, U>
{
    fn from(value: PackedDynamicGenericIntGraphNode<T, U>) -> Self {
        assert_eq!(value.bit_len as usize, N);

        Self { inner: value }
    }
}

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
    /// Allocate a new [`DynamicGenericInt`] using trivial or precomputed (if T is [`L1GgswCiphertext`]) encryptions
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
    /// If `val >= 2^n` (only when `n` is 63 or smaller)
    pub fn encrypt_secret(val: u128, enc: &Encryption, sk: &SecretKey, n: usize) -> Self {
        if n < 64 && val as u128 >= 0x1 << n {
            panic!("Out of bounds");
        }

        Self {
            bits: (0..n)
                .map(|i| {
                    let ct = T::encrypt_secret((val as u128 >> i) & 0x1 == 0x1, enc, sk);
                    Arc::new(AtomicRefCell::new(ct))
                })
                .collect(),
            _phantom: PhantomData,
        }
    }

    /// Decrypts this encrypted integer and returns the contained integer message.
    pub fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> u128 {
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
    pub fn with_decryption_fn<F>(&self, f: F) -> u128
    where
        F: Fn(&T) -> bool,
    {
        self.bits.iter().enumerate().fold(0u128, |s, (i, x)| {
            let x = AtomicRefCell::borrow(x);

            s + ((f(&x) as u128) << i)
        })
    }

    /// Create a trivial encryption of `val`.
    ///
    /// # Remarks
    /// If `T` is [`L1GgswCiphertext`], then the result will contain precomputed
    /// rather than trivial ciphertexts.
    ///
    /// # Panics
    /// If `val >= 2^n` (only when `n` is 63 or smaller)
    pub fn trivial(val: u128, enc: &Encryption, eval: &Evaluation, n: usize) -> Self {
        if n < 64 && val >= 0x1 << n {
            panic!("Out of bounds");
        }

        Self {
            bits: (0..n)
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
    /// Allocate a new [`GenericInt`] using trivial or precomputed (if T is [`L1GgswCiphertext`]) encryptions
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
    pub fn encrypt_secret(val: u128, enc: &Encryption, sk: &SecretKey) -> Self {
        Self {
            inner: DynamicGenericInt::encrypt_secret(val, enc, sk, N),
        }
    }

    /// Decrypts the encrypted integer
    pub fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> u128 {
        self.inner.decrypt(enc, sk)
    }

    /// Trivially encrypt the given integer
    pub fn trivial(val: u128, enc: &Encryption, eval: &Evaluation) -> Self {
        Self {
            inner: DynamicGenericInt::trivial(val, enc, eval, N),
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
    bit_len: u32,
    ct: Arc<AtomicRefCell<T>>,
    _phantom: PhantomData<U>,
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
    pub fn encrypt(val: u64, enc: &Encryption, pk: &PublicKey, n: usize) -> Self {
        let msg = Self::encode(val, enc, n);

        Self {
            bit_len: n as u32,
            ct: Arc::new(AtomicRefCell::new(T::encrypt(&msg, enc, pk))),
            _phantom: PhantomData,
        }
    }

    fn encode(val: u64, enc: &Encryption, n: usize) -> Polynomial<u64> {
        assert!(n >= 64 || val < 0x1 << n);
        assert!(n < T::poly_degree(&enc.params).0);

        let mut msg = Polynomial::<u64>::zero(T::poly_degree(&enc.params).0);

        for i in 0..n {
            msg.coeffs_mut()[i] = (val >> i) & 0x1;
        }

        msg
    }

    /// Decrypt this packed encrypted dynamic generic integer.
    pub fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> u64 {
        let n = self.bit_len as usize;

        assert!(n < T::poly_degree(&enc.params).0);
        let mut val = 0;

        let poly = <T as PolynomialCiphertextOps>::decrypt(&self.ct.borrow(), enc, sk);

        for i in 0..n {
            val += poly.coeffs()[i] << i;
        }

        val
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
    pub fn trivial_encrypt(val: u64, enc: &Encryption, n: usize) -> Self {
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
    pub fn encrypt(val: u64, enc: &Encryption, pk: &PublicKey) -> Self {
        Self {
            inner: PackedDynamicGenericInt::encrypt(val, enc, pk, N),
        }
    }

    /// Decrypts the encrypted integer
    pub fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> u64 {
        self.inner.decrypt(enc, sk)
    }

    /// Trivially encrypt the given integer
    pub fn trivial_encrypt(val: u64, enc: &Encryption) -> Self {
        Self {
            inner: PackedDynamicGenericInt::trivial_encrypt(val, enc, N),
        }
    }
}
