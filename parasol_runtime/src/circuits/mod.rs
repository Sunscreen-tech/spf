use std::sync::Arc;

use concurrency::AtomicRefCell;
use mux_circuits::sub::full_subtractor;

use crate::{Encryption, FheCircuit, L1GlweCiphertext};

pub mod add;
pub mod mul;
pub mod sub;

/// sub two ciphertexts together using a full subtractor. The borrow in is
/// optional, and if it is not provided, the borrow out will be ignored.
pub fn sub_circuit(
    width: usize,
    c1: &[Arc<AtomicRefCell<L1GlweCiphertext>>],
    c2: &[Arc<AtomicRefCell<L1GlweCiphertext>>],
    c_borrow: Option<&[Arc<AtomicRefCell<L1GlweCiphertext>>]>,
    enc: &Encryption,
) -> (FheCircuit, Vec<Arc<AtomicRefCell<L1GlweCiphertext>>>) {
    let mut graph = FheCircuit::new();
    let sub_circuit = full_subtractor(width, c_borrow.is_some());

    // order of the inputs for the ripple borrow suber is borrow then c1 then
    // c2
    let inputs = c_borrow
        .unwrap_or(&[])
        .iter()
        .chain(c1.iter().zip(c2.iter()).flat_map(|(a, b)| [a, b]))
        .cloned()
        .collect::<Vec<_>>();

    let outputs = graph.insert_mux_circuit_and_connect_inputs(&sub_circuit, &inputs, enc);

    (graph, outputs)
}
