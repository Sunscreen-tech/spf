use std::sync::Arc;

use mux_circuits::add::ripple_carry_adder;
use parasol_concurrency::AtomicRefCell;

use crate::{Encryption, FheCircuit, L1GlweCiphertext};

/// Add two ciphertexts together using a ripple carry adder. The carry in is
/// optional, and if it is not provided, the carry out will be ignored.
pub fn add_circuit(
    width: usize,
    c1: &[Arc<AtomicRefCell<L1GlweCiphertext>>],
    c2: &[Arc<AtomicRefCell<L1GlweCiphertext>>],
    c_carry: Option<&[Arc<AtomicRefCell<L1GlweCiphertext>>]>,
    enc: &Encryption,
) -> (FheCircuit, Vec<Arc<AtomicRefCell<L1GlweCiphertext>>>) {
    let mut graph = FheCircuit::new();
    let add_circuit = ripple_carry_adder(width, width, c_carry.is_some());

    // order of the inputs for the ripple carry adder is carry then c1 then
    // c2
    let inputs = c_carry
        .unwrap_or(&[])
        .iter()
        .chain(c1.iter().zip(c2.iter()).flat_map(|(a, b)| [a, b]))
        .cloned()
        .collect::<Vec<_>>();

    let outputs = graph.insert_mux_circuit_and_connect_inputs(&add_circuit, &inputs, enc);

    (graph, outputs)
}
