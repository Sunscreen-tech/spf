use std::{marker::PhantomData, sync::Arc};

use parasol_concurrency::AtomicRefCell;
use petgraph::stable_graph::NodeIndex;

use crate::{
    Encryption, FheEdge, FheOp, L1GlweCiphertext, L1LweCiphertext,
    fluent::{
        CiphertextOps, DynamicGenericIntGraphNodes, FheCircuitCtx, PackedDynamicGenericInt,
        PolynomialCiphertextOps, Sign,
    },
};

/// A graph node that represents a dynamic generic integer in packed form. See [`PackedDynamicGenericInt`] for a
/// description of packing.
pub struct PackedDynamicGenericIntGraphNode<T: CiphertextOps + PolynomialCiphertextOps, U: Sign> {
    pub(crate) bit_len: u32,
    pub(crate) id: NodeIndex,
    pub(crate) _phantom: PhantomData<(T, U)>,
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
