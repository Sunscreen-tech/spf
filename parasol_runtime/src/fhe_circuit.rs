use std::{
    collections::{HashMap, VecDeque},
    fmt::Write,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use mux_circuits::{MuxCircuit, MuxEdgeInfo, MuxOp};
use parasol_concurrency::AtomicRefCell;
use petgraph::{Direction, prelude::StableGraph, stable_graph::NodeIndex, visit::EdgeRef};

use crate::crypto::{
    Encryption, L0LweCiphertext, L1GgswCiphertext, L1GlevCiphertext, L1GlweCiphertext,
    L1LweCiphertext, ciphertext::CiphertextType,
};

/// An [`L0LweCiphertext`] that can be shared across threads.
pub type SharedL0LweCiphertext = Arc<AtomicRefCell<L0LweCiphertext>>;

/// An [`L1LweCiphertext`] that can be shared across threads.
pub type SharedL1LweCiphertext = Arc<AtomicRefCell<L1LweCiphertext>>;

/// An [`L1GlweCiphertext`] that can be shared across threads.
pub type SharedL1GlweCiphertext = Arc<AtomicRefCell<L1GlweCiphertext>>;

/// An [`L1GgswCiphertext`] that can be shared across threads.
pub type SharedL1GgswCiphertext = Arc<AtomicRefCell<L1GgswCiphertext>>;

/// An [`L1GlevCiphertext`] that can be shared across threads.
pub type SharedL1GlevCiphertext = Arc<AtomicRefCell<L1GlevCiphertext>>;

#[derive(Clone)]
/// A node in an [`FheCircuit`] representing a low-level crypto operation.
pub enum FheOp {
    /// An input to the computation of type [`SharedL0LweCiphertext`].
    InputLwe0(SharedL0LweCiphertext),

    /// An input to the computation of type [`SharedL1LweCiphertext`].
    InputLwe1(SharedL1LweCiphertext),

    /// An input to the computation of type [`SharedL1GlweCiphertext`].
    InputGlwe1(SharedL1GlweCiphertext),

    /// An input to the computation of type [`SharedL1GgswCiphertext`].
    InputGgsw1(SharedL1GgswCiphertext),

    /// An input to the computation of type [`SharedL1GlevCiphertext`].
    InputGlev1(SharedL1GlevCiphertext),

    /// An output resulting from the computation of type [`SharedL0LweCiphertext`].
    OutputLwe0(SharedL0LweCiphertext),

    /// An output resulting from the computation of type [`SharedL1LweCiphertext`].
    OutputLwe1(SharedL1LweCiphertext),

    /// An output resulting from the computation of type [`SharedL1GlweCiphertext`].
    OutputGlwe1(SharedL1GlweCiphertext),

    /// An output resulting from the computation of type [`SharedL1GgswCiphertext`].
    OutputGgsw1(SharedL1GgswCiphertext),

    /// An output resulting from the computation of type [`SharedL1GlevCiphertext`].
    OutputGlev1(SharedL1GlevCiphertext),

    /// Perform sample extraction, producing an LWE encryption of the `i`-th coefficient of a GLWE
    /// ciphertext's message. The contained [`usize`] member is `i`.
    SampleExtract(usize),

    /// Keyswitch a [`SharedL1LweCiphertext`] to [`SharedL0LweCiphertext`].
    KeyswitchL1toL0,

    /// Compute a homomorphic not operation.
    Not,

    /// Add 2 GLWE ciphertexts.
    GlweAdd,

    /// Compute a CMux of a GGSW and 2 GLWE ciphertexts.
    CMux,

    /// Compute a CMux of a GGSW and 2 GLEV ciphertexts.
    GlevCMux,

    /// Compute the outer product of [L1GgswCiphertext] x [L1GlweCiphertext] -> [L1GlweCiphertext] ciphertexts.
    MultiplyGgswGlwe,

    /// Run circuit bootstrapping, taking an [L0LweCiphertext] and producing a [L1GgswCiphertext] with reset noise.
    CircuitBootstrap,

    /// Turns a GLEV into a GGSW using scheme switching. Orders of magnitude faster than bootstrapping.
    SchemeSwitch,

    /// A [`L0LweCiphertext`] trivial encryption of zero.
    ZeroLwe0,

    /// A [`L0LweCiphertext`] trivial encryption of one.
    OneLwe0,

    /// A [`L1GlweCiphertext`] trivial encryption of zero.
    ZeroGlwe1,

    /// A [`L1GlweCiphertext`] trivial encryption of one.
    OneGlwe1,

    /// A [`L1GgswCiphertext`] precomputed encryption of zero.
    ZeroGgsw1,

    /// A [`L1GgswCiphertext`] precomputed encryption of one.
    OneGgsw1,

    /// A [`L1GlevCiphertext`] trivial encryption of zero.
    ZeroGlev1,

    /// A [`L1GlevCiphertext`] trivial encryption of one.
    OneGlev1,

    /// A Nop beacon operation that indicates no more FheOp uops will dispatch for the
    /// given parent instruction
    Retire,

    /// Do nothing.
    Nop,

    /// Negacyclically multiplies the message encrypted in a GLWE ciphertext by `X^N`. The contained
    /// [`usize`] member is `N`.
    MulXN(usize),
}

impl std::fmt::Debug for FheOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut potential_string = String::new();
        let op = match self {
            Self::InputLwe0(_) => "InputLwe0",
            Self::InputLwe1(_) => "InputLwe1",
            Self::InputGlwe1(_) => "InputGlwe1",
            Self::InputGgsw1(_) => "InputGgsw1",
            Self::InputGlev1(_) => "InputGlev1",
            Self::OutputLwe0(_) => "OutputLwe0",
            Self::OutputLwe1(_) => "OutputLwe1",
            Self::OutputGlwe1(_) => "OutputGlwe1",
            Self::OutputGgsw1(_) => "OutputGgsw1",
            Self::OutputGlev1(_) => "OutputGlev1",
            Self::SampleExtract(_) => "SampleExtract",
            Self::Not => "Not",
            Self::GlweAdd => "GlweAdd",
            Self::KeyswitchL1toL0 => "KeyswitchL1toL0",
            Self::CMux => "CMux",
            Self::GlevCMux => "GlevCMux",
            Self::MultiplyGgswGlwe => "MultiplyGgswGlwe",
            Self::CircuitBootstrap => "CircuitBootstrap",
            Self::ZeroLwe0 => "ZeroLwe0",
            Self::OneLwe0 => "ZeroLwe1",
            Self::ZeroGlwe1 => "ZeroGlwe1",
            Self::OneGlwe1 => "OneGlwe1",
            Self::ZeroGgsw1 => "ZeroGgsw1",
            Self::OneGgsw1 => "OneGgsw1",
            Self::ZeroGlev1 => "ZeroGlev1",
            Self::OneGlev1 => "OneGlev1",
            Self::Retire => "Retire",
            Self::Nop => "Nop",
            Self::MulXN(amt) => {
                write!(&mut potential_string, "Rotate({amt})")?;
                &potential_string
            }
            Self::SchemeSwitch => "SchemeSwitch",
        };

        write!(f, "{op}")
    }
}

#[derive(Copy, Clone, Debug)]
/// The input types for [`FheOp`]s in an [`FheCircuit`].
pub enum FheEdge {
    /// The value selected by a cmux when Sel is 0.
    Low,

    /// The value selected by a cmux when Sel is 1.
    High,

    /// The Select bit of a cmux.
    Sel,

    /// A unary input.
    Unary,

    /// An [L1GlweCiphertext] operand.
    Glwe,

    /// An [L1GgswCiphertext] operand.
    Ggsw,

    /// The left operand to a binary function.
    Left,

    /// The right operand to a binary function.
    Right,
}

#[derive(Debug)]
/// A directed graph of FHE operations that describe a computational circuit.
///
/// # Remarks
/// Well-formed circuits must be acyclic.
pub struct FheCircuit {
    /// The DAG.
    pub graph: StableGraph<FheOp, FheEdge>,
}

impl Deref for FheCircuit {
    type Target = StableGraph<FheOp, FheEdge>;

    fn deref(&self) -> &Self::Target {
        &self.graph
    }
}

impl DerefMut for FheCircuit {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.graph
    }
}

impl Default for FheCircuit {
    fn default() -> Self {
        Self::new()
    }
}

/// Which ciphertext type of operations to insert for the given [MuxCircuit].
pub enum MuxMode {
    /// Use the standard cmux and GLWE zero and one constants.
    Glwe,

    /// Use the GLEV cmux variant and zero, one constants.
    Glev,
}

impl MuxMode {
    pub fn mux(&self) -> FheOp {
        match self {
            Self::Glwe => FheOp::CMux,
            Self::Glev => FheOp::GlevCMux,
        }
    }

    pub fn zero(&self) -> FheOp {
        match self {
            Self::Glwe => FheOp::ZeroGlwe1,
            Self::Glev => FheOp::ZeroGlev1,
        }
    }

    pub fn one(&self) -> FheOp {
        match self {
            Self::Glwe => FheOp::OneGlwe1,
            Self::Glev => FheOp::OneGlev1,
        }
    }
}

impl FheCircuit {
    /// Create a new [`FheCircuit`]
    pub fn new() -> Self {
        Self {
            graph: StableGraph::new(),
        }
    }

    /// Insert the given mux tree connecting to the locations given by `inputs`.
    ///
    /// # Panics
    /// * If `inputs.len() != c.inputs.len()`
    pub fn insert_mux_circuit(
        &mut self,
        mux_circuit: &MuxCircuit,
        // The nodes in the FheCircuit that connect to the inputs of the MuxCircuit
        nodes_to_inputs: &[NodeIndex],
        mux_mode: MuxMode,
    ) -> Vec<NodeIndex> {
        assert_eq!(mux_circuit.inputs.len(), nodes_to_inputs.len());

        // Map the nodes from the MuxCircuit to the FheCircuit
        let mut node_renames = HashMap::new();

        // Create a vector to store the output nodes of the FheCircuit
        let mut outputs = vec![
            NodeIndex::default();
            mux_circuit
                .graph
                .node_weights()
                .filter(|x| matches!(x, MuxOp::Output(_)))
                .count()
        ];

        // Copy all non-I/O nodes
        for i in mux_circuit.graph.node_indices() {
            let mux_op = mux_circuit.graph[i];
            let fhe_equivalent_op = match mux_op {
                MuxOp::Mux => Some(mux_mode.mux()),
                MuxOp::One => Some(mux_mode.one()),
                MuxOp::Zero => Some(mux_mode.zero()),
                // TODO: Variables and Outputs can be skipped
                _ => None,
            };

            if let Some(n) = fhe_equivalent_op {
                let new_idx = self.graph.add_node(n);
                node_renames.insert(i, new_idx);
            }
        }

        // Hook up the inputs. We know the mux_circuit inputs are in the same
        // order as the nodes_to_inputs, so we can copy the mapping over.  We
        // are making the second graph in the following diagram from the first.
        //
        //                            ┌───┐
        //                       ┌───▶│a_0│
        //                       │    └───┘
        //                       │    ┌───┐
        // ┌─────────────────┐   ├───▶│a_1│
        // │ MuxOp::Variable │───┤    └───┘
        // └─────────────────┘   │      .
        //                       │      .
        //                       │      .
        //                       │    ┌───┐
        //                       └───▶│a_n│
        //                            └───┘
        //                            ┌────────────────────┐
        //                       ┌───▶│ nodes_renamed[a_0] │
        //                       │    └────────────────────┘
        //                       │    ┌────────────────────┐
        // ┌─────────────────┐   ├───▶│ nodes_renamed[a_1] │
        // │nodes_to_input[i]│───┤    └────────────────────┘
        // └─────────────────┘   │      .
        //                       │      .
        //                       │      .
        //                       │    ┌────────────────────┐
        //                       └───▶│ nodes_renamed[a_n] │
        //                            └────────────────────┘
        for (fhe_provided_op_index, mux_op_index) in
            nodes_to_inputs.iter().zip(mux_circuit.inputs.iter())
        {
            // All of our inputs should only be Variable nodes.
            if !matches!(mux_circuit.graph[*mux_op_index], MuxOp::Variable(_)) {
                panic!("Mux trees can only be connected to Variable nodes.");
            }

            // Since FHE operations are connected only to cmux operations, we
            // are only taking inputs in ggsw form (unless scheme switching, in
            // which case glev).
            if !matches!(
                self.graph[*fhe_provided_op_index],
                FheOp::InputGgsw1(_)
                    | FheOp::CircuitBootstrap
                    | FheOp::ZeroGgsw1
                    | FheOp::OneGgsw1
                    | FheOp::SchemeSwitch
            ) {
                panic!("Mux trees can only be connected to Ggsw, CBS, or Scheme switch nodes.");
            }

            // Connect the FHE input to all of the mux input outgoing edges.
            for e in mux_circuit
                .graph
                .edges_directed(*mux_op_index, petgraph::Direction::Outgoing)
            {
                let target = node_renames.get(&e.target()).unwrap();
                self.graph
                    .add_edge(*fhe_provided_op_index, *target, Self::map_edge(e.weight()));
            }
        }

        // Connect the outputs to our return value
        for i in mux_circuit
            .graph
            .node_indices()
            .filter(|n| matches!(mux_circuit.graph[*n], MuxOp::Output(_)))
        {
            let o = mux_circuit.graph[i];

            match o {
                MuxOp::Output(o) => {
                    let prev = mux_circuit
                        .graph
                        .edges_directed(i, petgraph::Direction::Incoming)
                        .nth(0)
                        .unwrap();
                    let idx = node_renames.get(&prev.source()).unwrap();

                    outputs[o as usize] = *idx;
                }
                _ => unreachable!(),
            }
        }

        // Connect the rest of the graph, save outputs
        for i in mux_circuit.graph.node_indices() {
            let node = mux_circuit.graph[i];

            // Variable was already handled when iterating through the inputs
            if matches!(node, MuxOp::Output(_)) || matches!(node, MuxOp::Variable(_)) {
                continue;
            }

            for e in mux_circuit
                .graph
                .edges_directed(i, petgraph::Direction::Outgoing)
            {
                let src = node_renames.get(&e.source()).unwrap();

                // dst may connect to an output node
                let dst = node_renames.get(&e.target());

                if let Some(dst) = dst {
                    self.graph.add_edge(*src, *dst, Self::map_edge(e.weight()));
                }
            }
        }

        outputs
    }

    /// Insert a [`MuxCircuit`] into the [`FheCircuit`] and emit outputs for each resulting
    /// [`L1GlweCiphertext`]. Returns the output node indices.
    pub fn insert_mux_circuit_output_glwe1_outputs(
        &mut self,
        mux_circuit: &MuxCircuit,
        nodes_to_inputs: &[NodeIndex],
        enc: &Encryption,
    ) -> Vec<NodeIndex> {
        let cmux_outputs = self.insert_mux_circuit(mux_circuit, nodes_to_inputs, MuxMode::Glwe);
        let glwe_outputs = (0..cmux_outputs.len())
            .map(|_| Arc::new(AtomicRefCell::new(enc.allocate_glwe_l1())))
            .collect::<Vec<_>>();

        cmux_outputs
            .iter()
            .zip(glwe_outputs.iter())
            .map(|(cmux_out, glwe_out)| {
                let o = self.graph.add_node(FheOp::OutputGlwe1(glwe_out.clone()));
                self.graph.add_edge(*cmux_out, o, FheEdge::Unary);
                o
            })
            .collect::<Vec<_>>()
    }

    /// Insert a [`MuxCircuit`] into the [`FheCircuit`] and emit outputs for each resulting
    /// [`L1GlweCiphertext`]. Returns the output ciphertexts.
    pub fn insert_mux_circuit_l1glwe_outputs(
        &mut self,
        mux_circuit: &MuxCircuit,
        nodes_to_inputs: &[NodeIndex],
        enc: &Encryption,
    ) -> Vec<Arc<AtomicRefCell<L1GlweCiphertext>>> {
        let glwe_outputs =
            self.insert_mux_circuit_output_glwe1_outputs(mux_circuit, nodes_to_inputs, enc);

        glwe_outputs
            .iter()
            .map(|x| {
                let node = self.graph.node_weight(*x).unwrap();
                match node {
                    FheOp::OutputGlwe1(x) => x.clone(),
                    _ => unreachable!(),
                }
            })
            .collect::<Vec<_>>()
    }

    /// Insert a mux circuit into the graph and connect the FHE circuit inputs
    /// to the mux circuit inputs. Returns the output nodes of the FHE circuit.
    pub fn insert_mux_circuit_and_connect_inputs(
        &mut self,
        mux_circuit: &MuxCircuit,
        inputs: &[Arc<AtomicRefCell<L1GlweCiphertext>>],
        enc: &Encryption,
    ) -> Vec<Arc<AtomicRefCell<L1GlweCiphertext>>> {
        let node_indices = inputs
            .iter()
            .map(|input| {
                let i = self.add_node(FheOp::InputGlwe1(input.clone()));
                let se = self.add_node(FheOp::SampleExtract(0));
                self.add_edge(i, se, FheEdge::Unary);
                let ks = self.add_node(FheOp::KeyswitchL1toL0);
                self.add_edge(se, ks, FheEdge::Unary);
                let cbs = self.add_node(FheOp::CircuitBootstrap);
                self.add_edge(ks, cbs, FheEdge::Unary);
                cbs
            })
            .collect::<Vec<_>>();

        self.insert_mux_circuit_l1glwe_outputs(mux_circuit, &node_indices, enc)
    }

    fn map_edge(e: &MuxEdgeInfo) -> FheEdge {
        match e {
            MuxEdgeInfo::High => FheEdge::High,
            MuxEdgeInfo::Low => FheEdge::Low,
            MuxEdgeInfo::Select => FheEdge::Sel,
            MuxEdgeInfo::Output => unreachable!(),
        }
    }
}

impl From<StableGraph<FheOp, FheEdge>> for FheCircuit {
    fn from(value: StableGraph<FheOp, FheEdge>) -> Self {
        Self { graph: value }
    }
}

/// Removes any nodes not reachable from any of `nodes` to optimize a computation.
///
/// # Remarks
/// This can remove unused inputs from the graph!
pub fn prune<N: Clone, E: Clone>(
    graph: &StableGraph<N, E>,
    nodes: &[NodeIndex],
) -> (StableGraph<N, E>, HashMap<NodeIndex, NodeIndex>) {
    let mut out_graph = StableGraph::new();
    let mut queue = VecDeque::new();
    let mut rename = HashMap::new();

    for i in nodes {
        queue.push_back(*i);
    }

    // Copy all the nodes reachable from `nodes` to the new graph.
    while !queue.is_empty() {
        let cur_id = queue.pop_front().unwrap();

        rename
            .entry(cur_id)
            .or_insert_with(|| out_graph.add_node(graph.node_weight(cur_id).unwrap().to_owned()));

        for next in graph.neighbors_directed(cur_id, Direction::Incoming) {
            if let std::collections::hash_map::Entry::Vacant(e) = rename.entry(next) {
                let new_id = out_graph.add_node(graph.node_weight(next).unwrap().to_owned());
                e.insert(new_id);
                queue.push_back(next);
            }
        }
    }

    for (old, _) in rename.iter() {
        for e in graph.edges_directed(*old, Direction::Incoming) {
            let source = *rename.get(&e.source()).unwrap();
            let target = *rename.get(&e.target()).unwrap();

            out_graph.add_edge(source, target, e.weight().to_owned());
        }
    }

    (out_graph, rename)
}

/// Inserts conversions between the result at `cur_node` from an `in_type`
/// ciphertext to an `out_type` ciphertext`. Returns the index of the node
/// of the `out_type` ciphertext.
///
/// # Remarks
/// Can recurse up to 4 times.
pub fn insert_ciphertext_conversion(
    graph: &mut FheCircuit,
    cur_node: NodeIndex,
    in_type: CiphertextType,
    out_type: CiphertextType,
) -> NodeIndex {
    if in_type == out_type {
        return cur_node;
    }

    let (conv_idx, next_type) = match in_type {
        CiphertextType::L0LweCiphertext => {
            let idx = graph.add_node(FheOp::CircuitBootstrap);
            graph.add_edge(cur_node, idx, FheEdge::Unary);

            (idx, CiphertextType::L1GgswCiphertext)
        }
        CiphertextType::L1GgswCiphertext => {
            if out_type == CiphertextType::L1GlevCiphertext {
                let idx = graph.add_node(FheOp::GlevCMux);
                let zero = graph.add_node(FheOp::ZeroGlev1);
                let one = graph.add_node(FheOp::OneGlev1);

                graph.add_edge(zero, idx, FheEdge::Low);
                graph.add_edge(one, idx, FheEdge::High);
                graph.add_edge(cur_node, idx, FheEdge::Sel);

                (idx, out_type)
            } else {
                let idx = graph.add_node(FheOp::MultiplyGgswGlwe);
                let one = graph.add_node(FheOp::OneGlwe1);

                graph.add_edge(one, idx, FheEdge::Glwe);
                graph.add_edge(cur_node, idx, FheEdge::Ggsw);

                (idx, CiphertextType::L1GlweCiphertext)
            }
        }
        CiphertextType::L1GlweCiphertext => {
            let idx = graph.add_node(FheOp::SampleExtract(0));
            graph.add_edge(cur_node, idx, FheEdge::Unary);

            (idx, CiphertextType::L1LweCiphertext)
        }
        CiphertextType::L1LweCiphertext => {
            let idx = graph.add_node(FheOp::KeyswitchL1toL0);
            graph.add_edge(cur_node, idx, FheEdge::Unary);

            (idx, CiphertextType::L0LweCiphertext)
        }
        CiphertextType::L1GlevCiphertext => {
            let idx = graph.add_node(FheOp::SchemeSwitch);
            graph.add_edge(cur_node, idx, FheEdge::Unary);

            (idx, CiphertextType::L1GgswCiphertext)
        }
    };

    insert_ciphertext_conversion(graph, conv_idx, next_type, out_type)
}
