#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! This crate provides algorithms for building multiplexer circuits as well as a standard library
//! of common operations.

use std::{collections::HashMap, convert::Infallible, mem::size_of};

use biodivine_lib_bdd::Bdd;
pub use graph_ops::Bit;
use graph_ops::forward_traverse;
use opt::{EdgeOps, Operation, common_subexpression_elimination};
use petgraph::{
    Direction,
    graph::NodeIndex,
    stable_graph::{EdgeReference, StableGraph},
    visit::{EdgeRef, NodeRef},
};
use serde::{Deserialize, Serialize};

/// Integer Adders
pub mod add;

/// Bitwise-and
pub mod and;

/// Bitshift
pub mod bitshift;

/// Integer comparisons.
pub mod comparisons;

/// Errors that can occur in this crate.
pub mod error;

/// Operations
mod graph_ops;

/// Integer multipliers
pub mod mul;

/// Integer negator
pub mod neg;

/// Circuit optimizations.
pub mod opt;

/// Bitwise-or
pub mod or;

/// Integer subtractors
pub mod sub;

/// Misc operations on integers.
pub mod util;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// The operations in a [`MuxCircuit`]. These operations are connected with [`MuxEdgeInfo`]s.
pub enum MuxOp {
    /// The literal value '1'.
    ///
    /// # Remarks
    /// [`MuxOp::One`] takes no inputs. Violating this results in a malformed circuit.
    One,

    /// The literal value '0'.
    ///
    /// # Remarks
    /// [`MuxOp::Zero`] takes no inputs. Violating this results in a malformed circuit.
    Zero,

    /// A multiplexer. Takes 3 inputs: high, low, and select.
    ///
    /// # Remarks
    /// The output of a multiplexer is the low input when select is `0` and
    /// high when select is `1`.`
    ///
    /// [`MuxOp::Mux`] takes exactly one each of [`MuxEdgeInfo::Low`], [`MuxEdgeInfo::High`],
    /// and [`MuxEdgeInfo::Select`]. Violating this results in a malformed circuit.
    Mux,

    /// The `i`th input variable to the circuit, where `i` is the struct member.
    ///
    /// # Remarks
    /// Input variables have no inputs. Furthermore, for a circuit with N inputs, each input index
    /// `i` in 0..N must appear exactly once. Violating this results in a malformed circuit.
    Variable(u32),

    /// The `i`th output variable, where `i` is the struct member.
    ///
    /// # Remarks
    /// Output variables have one input of type [`MuxEdgeInfo::Output`]. Furthermore, for a circuit
    /// with N outputs, each output index `i` in 0..N must appear exactly once. Violating this
    /// results in a malformed circuit.
    Output(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// The wires of the [`MuxCircuit`] connecting [`MuxOp`]s.
pub enum MuxEdgeInfo {
    /// Connects a circuit element to the "low" input of a [`MuxOp::Mux`]
    Low,

    /// Connects a circuit element to the "high" input of a [`MuxOp::Mux`]
    High,

    /// Connects a circuit element to the "select" input of a [`MuxOp::Mux`]
    Select,

    /// Connects a circuit element to the "output" input of a [`MuxOp::Output`]
    Output,
}

impl EdgeOps for MuxEdgeInfo {
    fn binary_operand_type(&self) -> Option<opt::BinaryOperandInfo> {
        None
    }

    fn mux_operand_type(&self) -> Option<opt::MuxOperandInfo> {
        match self {
            Self::Low => Some(opt::MuxOperandInfo::Low),
            Self::High => Some(opt::MuxOperandInfo::High),
            Self::Select => Some(opt::MuxOperandInfo::Select),
            _ => None,
        }
    }
}

impl Operation for MuxOp {
    fn is_binary(&self) -> bool {
        false
    }

    fn is_commutative(&self) -> bool {
        false
    }

    fn is_mux(&self) -> bool {
        matches!(self, Self::Mux)
    }

    fn is_ordered(&self) -> bool {
        false
    }

    fn is_unary(&self) -> bool {
        false
    }

    fn is_unordered(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A DAG describing a multiplexer tree.
///
/// # Remarks
/// When used in the context of FHE, [`MuxOp::Mux`]s should connect to [`MuxEdgeInfo::Low`] or
/// [`MuxEdgeInfo::High`] edges on another [`MuxOp::Mux`] or a [`MuxOp::Output`]. Additionally,
/// [`MuxOp::Variable`]s should connect to the [`MuxEdgeInfo::Select`] lines of [`MuxOp::Mux`]
/// operations.
///
/// Well-formed [`MuxCircuit`]s must additionally contain no cycles.
pub struct MuxCircuit {
    /// The DAG describing the multiplexer tree.
    pub graph: StableGraph<MuxOp, MuxEdgeInfo>,

    /// Inputs to the multiplexer tree.
    pub inputs: Vec<NodeIndex>,
}

#[derive(Debug, Clone, Copy)]
/// Metrcs for a [`MuxCircuit`]
pub struct MuxCircuitInfo {
    /// The number of [`MuxOp::Mux`] operations.
    pub mux_gates: usize,

    /// The number of [`MuxOp::Variable`] operations.
    pub inputs: usize,

    /// The number of [`MuxOp::Output`] operations.
    pub outputs: usize,
}

#[derive(Hash, PartialEq, Eq)]
/// The [`NodeIndex`]es of a [`MuxOp::Mux`]'s parent operations.
pub struct MuxInputs {
    /// The node corresponding to [`MuxEdgeInfo::Select`].
    pub sel_id: NodeIndex,

    /// The node corresponding to [`MuxEdgeInfo::High`].
    pub low_id: NodeIndex,

    /// The node corresponding to [`MuxEdgeInfo::Low`].
    pub high_id: NodeIndex,
}

impl MuxCircuit {
    /// Get the operation counts of this [`MuxCircuit`].
    pub fn metrics(&self) -> MuxCircuitInfo {
        MuxCircuitInfo {
            mux_gates: self
                .graph
                .node_weights()
                .filter(|x| matches!(x, MuxOp::Mux))
                .count(),
            inputs: self
                .graph
                .node_weights()
                .filter(|x| matches!(x, MuxOp::Variable(_)))
                .count(),
            outputs: self
                .graph
                .node_weights()
                .filter(|x| matches!(x, MuxOp::Output(_)))
                .count(),
        }
    }

    #[inline(always)]
    #[allow(unused)]
    fn compute_inputs(graph: &StableGraph<MuxOp, MuxEdgeInfo>) -> Vec<NodeIndex> {
        let nodes = graph
            .node_indices()
            .filter(|x| matches!(graph.node_weight(*x), Some(MuxOp::Variable(_))))
            .collect::<Vec<_>>();

        let mut inputs = vec![NodeIndex::default(); nodes.len()];

        for i in nodes {
            let n = graph.node_weight(i).unwrap();

            if let MuxOp::Variable(x) = n {
                inputs[*x as usize] = i;
            } else {
                unreachable!();
            }
        }

        inputs
    }

    /// Returns the parents of a [`MuxOp::Mux`] operations.
    pub fn get_mux_inputs(&self, node_id: NodeIndex) -> MuxInputs {
        assert!(matches!(self.graph.node_weight(node_id), Some(MuxOp::Mux)));

        let mut edges = self
            .graph
            .edges_directed(node_id, petgraph::Direction::Incoming);

        let mut low = None;
        let mut high = None;
        let mut sel = None;

        let mut assign_input = |e: EdgeReference<MuxEdgeInfo, u32>| match e.weight() {
            MuxEdgeInfo::Select => sel = Some(e.source()),
            MuxEdgeInfo::Low => low = Some(e.source()),
            MuxEdgeInfo::High => high = Some(e.source()),
            _ => unreachable!(),
        };

        assign_input(edges.next().unwrap());
        assign_input(edges.next().unwrap());
        assign_input(edges.next().unwrap());
        assert_eq!(edges.next(), None);

        MuxInputs {
            sel_id: sel.unwrap(),
            low_id: low.unwrap(),
            high_id: high.unwrap(),
        }
    }

    /// Run common-subexpression elimination on the circuit to collapse redundant [`MuxOp::Mux`]
    /// operations.
    pub fn optimize(&mut self) {
        common_subexpression_elimination(&mut self.graph);
        self.compact_indices();
    }

    /// Allows one to remap inputs to make the MUX more convenient to use.
    ///
    /// # Remarks
    /// Given a desired number of `deduped_count` inputs, run the function `f` to
    /// determine the desired index of each of the present inputs. Delete all the existing
    /// inputs, insert `deduped_count` new ones and remap all the deleted nodes to the
    /// index given by `f`.
    pub fn remap_inputs<F: Fn() -> Vec<u32>>(&mut self, deduped_count: u32, f: F) {
        let encoded = f();
        assert_eq!(self.inputs.len(), encoded.len());
        let mut input_map = HashMap::<u32, Vec<NodeIndex>>::new();

        for (i, n) in encoded.iter().copied().zip(self.inputs.iter().copied()) {
            input_map.entry(i).or_insert_with(Vec::new);

            input_map.get_mut(&i).unwrap().push(n);
        }

        let deduped_inputs = (0..deduped_count)
            .map(|idx| self.graph.add_node(MuxOp::Variable(idx)))
            .collect::<Vec<_>>();

        assert_eq!(deduped_inputs.len(), input_map.len());

        let mut edges_tmp = vec![];

        for (i, deduped) in deduped_inputs.iter().enumerate() {
            let nodes = input_map.get(&(i as u32)).unwrap();

            for orig in nodes {
                // Can't mutate the graph while we're iterating over edges, so copy
                // the edge indices into a temp buffer.
                edges_tmp.clear();
                edges_tmp.extend(
                    self.graph
                        .edges_directed(*orig, Direction::Outgoing)
                        .map(|e| (e.target().id(), *e.weight())),
                );

                // Copy all the existing edges over to the deduped node
                for e in edges_tmp.iter() {
                    self.graph.add_edge(*deduped, e.0, e.1);
                }

                // Remove the original input.
                self.graph.remove_node(*orig);
            }
        }

        self.compact_indices();
    }

    /// Compacts all the node indices in the graph and recomputes the input nodes.
    fn compact_indices(&mut self) {
        let graph =
            petgraph::stable_graph::StableGraph::from(petgraph::Graph::from(self.graph.clone()));
        self.graph = graph;

        // Recompute the inputs
        let mut indices = self
            .graph
            .node_indices()
            .filter_map(|n| {
                if let MuxOp::Variable(x) = self.graph.node_weight(n).unwrap() {
                    Some((*x, n))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        indices.sort_by(|a, b| a.0.cmp(&b.0));

        self.inputs = indices.into_iter().map(|x| x.1).collect::<Vec<_>>();
    }
}

impl From<&[Bdd]> for MuxCircuit {
    /// # Remarks
    /// Each binary decision diagram must have been created from the same input variables.
    fn from(value: &[Bdd]) -> Self {
        let mut circuit = StableGraph::new();
        let mut max_inputs = 0u32;
        let mut zero_node = None;
        let mut one_node = None;

        // Each BDD creates one output variable.
        for (i, bdd) in value.iter().enumerate() {
            let ser = bdd.to_bytes();

            // The BDD should have at least one node.
            assert_eq!(ser.len() % (size_of::<u16>() + 2 * size_of::<u32>()), 0);
            assert!(!ser.is_empty());

            // Either a 0 or 1 node will be first and its variable id will equal the
            // number of variables.
            let mut last_node = NodeIndex::from(0);
            let mut added_nodes = vec![];

            for node in ser.chunks(size_of::<u16>() + 2 * size_of::<u32>()) {
                // Infallable since len = 3 * sizeof(u32)
                let var_id = u16::from_le_bytes(node[0..2].try_into().unwrap()) as u32;
                let low_edge = u32::from_le_bytes(node[2..6].try_into().unwrap());
                let high_edge = u32::from_le_bytes(node[6..10].try_into().unwrap());

                max_inputs = u32::max(max_inputs, var_id);

                let node = if high_edge == 0 && low_edge == 0 {
                    if zero_node.is_none() {
                        zero_node = Some(circuit.add_node((MuxOp::Zero, var_id)));
                    }
                    zero_node.unwrap()
                } else if high_edge == 1 && low_edge == 1 {
                    if one_node.is_none() {
                        one_node = Some(circuit.add_node((MuxOp::One, var_id)));
                    }
                    one_node.unwrap()
                } else {
                    circuit.add_node((MuxOp::Mux, var_id))
                };

                added_nodes.push(node);

                if low_edge != high_edge {
                    circuit.add_edge(added_nodes[low_edge as usize], node, MuxEdgeInfo::Low);
                    circuit.add_edge(added_nodes[high_edge as usize], node, MuxEdgeInfo::High);
                }

                last_node = node;
            }

            // Stick an output on the end of the last node.
            let output = circuit.add_node((MuxOp::Output(i as u32), 0));
            circuit.add_edge(last_node, output, MuxEdgeInfo::Output);
        }

        // Create input nodes.
        let mut input_node_ids = Vec::with_capacity(max_inputs as usize);

        for i in 0..max_inputs {
            input_node_ids.push(circuit.add_node((MuxOp::Variable(i), 0)));
        }

        let node_indicies = circuit.node_indices().collect::<Vec<_>>();

        // Tie the select lines to the MUX inputs.
        for n in node_indicies {
            let (op, var_id) = circuit[n];

            if let MuxOp::Mux = op {
                let var_node_id = input_node_ids[var_id as usize];
                circuit.add_edge(var_node_id, n, MuxEdgeInfo::Select);
            }
        }

        // Map away the var_ids, as we only needed them to route the select lines
        // to MUXs
        let circuit = circuit.map(|_, (n, _)| *n, |_, e| *e);

        Self {
            graph: circuit,
            inputs: input_node_ids,
        }
    }
}

/// Run the given inputs through [`MuxCircuit`] and return the resuling output [`Bit`]s
pub fn test_mux_circuit(circuit: &MuxCircuit, inputs: &[Bit]) -> Vec<Bit> {
    assert_eq!(
        inputs.len(),
        circuit
            .graph
            .node_weights()
            .filter(|x| matches!(x, MuxOp::Variable(_)))
            .count()
    );

    let mut data = vec![false; circuit.graph.node_count()];

    forward_traverse(&circuit.graph, |query, n| {
        let node = query.get_node(n).unwrap();

        match node {
            MuxOp::Variable(x) => {
                data[n.index()] = *inputs[*x as usize];
            }
            MuxOp::One => {
                data[n.index()] = true;
            }
            MuxOp::Zero => {
                data[n.index()] = false;
            }
            MuxOp::Output(_) => {
                let prev = query.edges_directed(n, Direction::Incoming).next().unwrap();

                data[n.index()] = data[prev.source().index()];
            }
            MuxOp::Mux => {
                let mux_inputs = circuit.get_mux_inputs(n);

                let sel = data[mux_inputs.sel_id.index()];
                let high = data[mux_inputs.high_id.index()];
                let low = data[mux_inputs.low_id.index()];

                let res = if sel { high } else { low };

                data[n.index()] = res;
            }
        };

        Ok::<_, Infallible>(())
    })
    .unwrap();

    let mut outputs = circuit
        .graph
        .node_indices()
        .filter_map(|x| {
            let node = circuit.graph[x];

            if let MuxOp::Output(idx) = node {
                Some((x, idx))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    outputs.sort();
    outputs.iter().map(|(x, _)| Bit(data[x.index()])).collect()
}

/// Converts a value into a vector of bits.
pub fn convert_value_to_bits(val: u128, width: u32) -> Vec<bool> {
    let mut bits = Vec::with_capacity(width as usize);

    for i in 0..width {
        bits.push((val >> i) & 1 == 1);
    }

    bits
}

#[cfg(test)]
mod tests {
    use biodivine_lib_bdd::{BddVariableSet, BddVariableSetBuilder};

    use super::*;

    #[test]
    fn from_bdd() {
        let mut builder = BddVariableSetBuilder::new();
        builder.make(&["a0", "b0", "a1", "b1"]);
        let variables: BddVariableSet = builder.build();

        let x = variables
            .eval_expression_string("(a0 & !b0) | (a0 & b0 & a1 & !b1) | (!a0 & !a0 & a1 & !b1)");

        let circuit = MuxCircuit::from(vec![x].as_slice());

        assert_eq!(circuit.inputs.len(), variables.num_vars() as usize);

        // Should have 4 input nodes, 1 output node, a one and zero node, and 4
        // MUX nodes.
        assert_eq!(circuit.graph.node_count(), 11);

        assert_eq!(circuit.graph[NodeIndex::from(0)], MuxOp::Zero);
        assert_eq!(circuit.graph[NodeIndex::from(1)], MuxOp::One);
        assert_eq!(circuit.graph[NodeIndex::from(2)], MuxOp::Mux);
        assert_eq!(circuit.graph[NodeIndex::from(3)], MuxOp::Mux);
        assert_eq!(circuit.graph[NodeIndex::from(4)], MuxOp::Mux);
        assert_eq!(circuit.graph[NodeIndex::from(5)], MuxOp::Mux);
        assert_eq!(circuit.graph[NodeIndex::from(6)], MuxOp::Output(0));
        assert_eq!(circuit.graph[NodeIndex::from(7)], MuxOp::Variable(0));
        assert_eq!(circuit.graph[NodeIndex::from(8)], MuxOp::Variable(1));
        assert_eq!(circuit.graph[NodeIndex::from(9)], MuxOp::Variable(2));
        assert_eq!(circuit.graph[NodeIndex::from(10)], MuxOp::Variable(3));

        // TODO, validate edges
    }

    #[test]
    fn elided_variables() {
        let mut builder = BddVariableSetBuilder::new();
        builder.make(&["a0", "b0", "a1", "b1"]);
        let variables: BddVariableSet = builder.build();

        let x = variables.eval_expression_string("b1");

        let circuit = MuxCircuit::from(vec![x].as_slice());

        assert_eq!(circuit.inputs.len(), variables.num_vars() as usize);
        assert_eq!(circuit.graph.node_count(), 8);

        assert_eq!(circuit.graph[NodeIndex::from(0)], MuxOp::Zero);
        assert_eq!(circuit.graph[NodeIndex::from(1)], MuxOp::One);
        assert_eq!(circuit.graph[NodeIndex::from(2)], MuxOp::Mux);
        assert_eq!(circuit.graph[NodeIndex::from(3)], MuxOp::Output(0));
        assert_eq!(circuit.graph[NodeIndex::from(4)], MuxOp::Variable(0));
        assert_eq!(circuit.graph[NodeIndex::from(5)], MuxOp::Variable(1));
        assert_eq!(circuit.graph[NodeIndex::from(6)], MuxOp::Variable(2));
        assert_eq!(circuit.graph[NodeIndex::from(7)], MuxOp::Variable(3));
    }

    #[test]
    fn from_multiple_bdds() {
        let mut builder = BddVariableSetBuilder::new();
        builder.make(&["a0", "b0", "a1", "b1"]);
        let variables: BddVariableSet = builder.build();

        let x = variables.eval_expression_string("b1");
        let y = variables.eval_expression_string("!a1");

        let circuit = MuxCircuit::from([x, y].as_slice());

        assert_eq!(circuit.graph[NodeIndex::from(0)], MuxOp::Zero);
        assert_eq!(circuit.graph[NodeIndex::from(1)], MuxOp::One);
        assert_eq!(circuit.graph[NodeIndex::from(2)], MuxOp::Mux);
        assert_eq!(circuit.graph[NodeIndex::from(3)], MuxOp::Output(0));
        assert_eq!(circuit.graph[NodeIndex::from(4)], MuxOp::Mux);
        assert_eq!(circuit.graph[NodeIndex::from(5)], MuxOp::Output(1));
        assert_eq!(circuit.graph[NodeIndex::from(6)], MuxOp::Variable(0));
        assert_eq!(circuit.graph[NodeIndex::from(7)], MuxOp::Variable(1));
        assert_eq!(circuit.graph[NodeIndex::from(8)], MuxOp::Variable(2));
        assert_eq!(circuit.graph[NodeIndex::from(9)], MuxOp::Variable(3));
    }

    #[test]
    fn can_optimize_mux_circuit() {
        let mut graph = StableGraph::new();
        let a = graph.add_node(MuxOp::Variable(0));
        let b = graph.add_node(MuxOp::Variable(1));
        let sel = graph.add_node(MuxOp::Variable(2));

        let mux_1 = graph.add_node(MuxOp::Mux);
        let mux_2 = graph.add_node(MuxOp::Mux);

        let out_1 = graph.add_node(MuxOp::Output(0));
        let out_2 = graph.add_node(MuxOp::Output(1));

        graph.add_edge(a, mux_1, MuxEdgeInfo::Low);
        graph.add_edge(b, mux_1, MuxEdgeInfo::High);
        graph.add_edge(sel, mux_1, MuxEdgeInfo::Select);

        graph.add_edge(a, mux_2, MuxEdgeInfo::Low);
        graph.add_edge(b, mux_2, MuxEdgeInfo::High);
        graph.add_edge(sel, mux_2, MuxEdgeInfo::Select);

        graph.add_edge(mux_1, out_1, MuxEdgeInfo::Output);
        graph.add_edge(mux_2, out_2, MuxEdgeInfo::Output);

        let mut mux_circuit = MuxCircuit {
            graph: graph.clone(),
            inputs: MuxCircuit::compute_inputs(&graph),
        };

        mux_circuit.optimize();
        let opt = mux_circuit;

        assert_eq!(opt.graph.node_weights().count(), 6);
        assert_eq!(
            *opt.graph.node_weight(opt.inputs[0]).unwrap(),
            MuxOp::Variable(0)
        );
        assert_eq!(
            *opt.graph.node_weight(opt.inputs[1]).unwrap(),
            MuxOp::Variable(1)
        );
        assert_eq!(
            *opt.graph.node_weight(opt.inputs[2]).unwrap(),
            MuxOp::Variable(2)
        );
        assert_eq!(
            opt.graph
                .node_weights()
                .filter(|x| matches!(x, MuxOp::Mux))
                .count(),
            1
        );

        let output_0 = opt
            .graph
            .node_indices()
            .find(|x| matches!(opt.graph.node_weight(*x).unwrap(), MuxOp::Output(0)))
            .unwrap();

        let output_1 = opt
            .graph
            .node_indices()
            .find(|x| matches!(opt.graph.node_weight(*x).unwrap(), MuxOp::Output(1)))
            .unwrap();

        let mut out_0_edges = opt.graph.edges_directed(output_0, Direction::Incoming);
        let out_0_edge = out_0_edges.next().unwrap().weight();
        assert!(out_0_edges.next().is_none());

        assert_eq!(*out_0_edge, MuxEdgeInfo::Output);

        let mut out_1_edges = opt.graph.edges_directed(output_1, Direction::Incoming);
        let out_1_edge = out_1_edges.next().unwrap().weight();
        assert!(out_1_edges.next().is_none());

        assert_eq!(*out_1_edge, MuxEdgeInfo::Output);
    }
}
