use bumpalo::Bump;
use mux_circuits::{add::ripple_carry_adder, and::make_and_circuit, comparisons::{compare_equal, compare_not_equal}, sub::full_subtractor};
use petgraph::stable_graph::NodeIndex;
use std::marker::PhantomData;

use crate::{fluent::{BitNode, CiphertextOps, DynamicGenericInt, FheCircuitCtx, Muxable, PackedDynamicGenericIntGraphNode, Sign}, prune, Encryption, FheEdge, FheOp, L1GgswCiphertext, L1GlweCiphertext};

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
