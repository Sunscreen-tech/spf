use std::sync::{Arc, Mutex};

use mux_circuits::and::make_and_circuit;
use parasol_concurrency::AtomicRefCell;
use sunscreen_tfhe::entities::Polynomial;

use crate::{
    CircuitProcessor, DEFAULT_128, FheEdge,
    crypto::{L0LweCiphertext, L1GlweCiphertext},
    fhe_circuit::{FheCircuit, FheOp},
    test_utils::{get_encryption_128, get_evaluation_128, get_secret_keys_128, make_uproc_128},
};

mod faults;

fn run_uop_program(graph: &FheCircuit) {
    let (processor, flow) = make_uproc_128();

    processor
        .lock()
        .unwrap()
        .run_graph_blocking(graph, &flow)
        .unwrap();
}

fn run_uop_program_with_fc_len(graph: &FheCircuit, fc_len: usize) {
    let (processor, flow) =
        CircuitProcessor::new(fc_len, None, &get_evaluation_128(), &get_encryption_128());

    let processor = Mutex::new(processor);

    processor
        .lock()
        .unwrap()
        .run_graph_blocking(graph, &flow)
        .unwrap();
}

fn encrypt_lwe0(val: bool) -> Arc<AtomicRefCell<L0LweCiphertext>> {
    let ct = get_encryption_128().encrypt_lwe_l0_secret(val, &get_secret_keys_128());

    Arc::new(AtomicRefCell::new(ct))
}

fn encrypt_glwe1(val: &[u64]) -> Arc<AtomicRefCell<L1GlweCiphertext>> {
    let poly = Polynomial::new(val);

    let ct = get_encryption_128().encrypt_glwe_l1_secret(&poly, &get_secret_keys_128());

    Arc::new(AtomicRefCell::new(ct))
}

#[test]
fn can_copy_lwe0() {
    let input = encrypt_lwe0(true);
    let output = encrypt_lwe0(false);

    let mut graph = FheCircuit::new();

    let i = graph.add_node(FheOp::InputLwe0(input.clone()));
    let o = graph.add_node(FheOp::OutputLwe0(output.clone()));
    graph.add_edge(i, o, crate::FheEdge::Unary);

    run_uop_program(&graph);

    assert_eq!(
        AtomicRefCell::borrow(&input).0,
        AtomicRefCell::borrow(&output).0,
    );
}

#[test]
fn glwe_zero() {
    let enc = get_encryption_128();

    let output = Arc::new(AtomicRefCell::new(enc.allocate_glwe_l1()));

    let mut graph = FheCircuit::new();
    let i = graph.add_node(FheOp::ZeroGlwe1);
    let o = graph.add_node(FheOp::OutputGlwe1(output.clone()));

    graph.add_edge(i, o, FheEdge::Unary);

    run_uop_program(&graph);

    assert_eq!(
        AtomicRefCell::borrow(&output.clone()).0,
        enc.trivial_glwe_l1_zero().0
    )
}

#[test]
fn glwe_one() {
    let enc = get_encryption_128();

    let output = Arc::new(AtomicRefCell::new(enc.allocate_glwe_l1()));

    let mut graph = FheCircuit::new();
    let i = graph.add_node(FheOp::OneGlwe1);
    let o = graph.add_node(FheOp::OutputGlwe1(output.clone()));

    graph.add_edge(i, o, FheEdge::Unary);

    run_uop_program(&graph);

    assert_eq!(
        AtomicRefCell::borrow(&output.clone()).0,
        enc.trivial_glwe_l1_one().0
    )
}

#[test]
fn can_sample_extract() {
    let enc = get_encryption_128();

    let output = Arc::new(AtomicRefCell::new(enc.allocate_lwe_l1()));

    let mut graph = FheCircuit::new();
    let i = graph.add_node(FheOp::OneGlwe1);
    let se = graph.add_node(FheOp::SampleExtract(0));
    let o = graph.add_node(FheOp::OutputLwe1(output.clone()));

    graph.add_edge(i, se, FheEdge::Unary);
    graph.add_edge(se, o, FheEdge::Unary);

    run_uop_program(&graph);

    assert_eq!(
        AtomicRefCell::borrow(&output.clone()).0,
        enc.trivial_lwe_l1_one().0
    )
}

#[test]
fn can_keyswitch() {
    let enc = get_encryption_128();
    let secret_key = get_secret_keys_128();

    let input = Arc::new(AtomicRefCell::new(
        enc.encrypt_lwe_l1_secret(true, &secret_key),
    ));

    let output = Arc::new(AtomicRefCell::new(enc.allocate_lwe_l0()));

    let mut graph = FheCircuit::new();
    let i = graph.add_node(FheOp::InputLwe1(input.clone()));
    let ks = graph.add_node(FheOp::KeyswitchL1toL0);
    let o = graph.add_node(FheOp::OutputLwe0(output.clone()));

    graph.add_edge(i, ks, FheEdge::Unary);
    graph.add_edge(ks, o, FheEdge::Unary);

    run_uop_program(&graph);

    assert!(enc.decrypt_lwe_l0(&AtomicRefCell::borrow(&output.clone()), &secret_key));
}

#[test]
fn can_cmux() {
    let secret = get_secret_keys_128();
    let enc = get_encryption_128();

    let a = encrypt_glwe1(&vec![0; DEFAULT_128.l1_poly_degree().0]);

    let b = encrypt_glwe1(&vec![1; DEFAULT_128.l1_poly_degree().0]);

    let sel = encrypt_lwe0(true);

    let output = Arc::new(AtomicRefCell::new(enc.allocate_glwe_l1()));

    let mut graph = FheCircuit::new();

    let sel_in = graph.add_node(FheOp::InputLwe0(sel.clone()));
    let a_in = graph.add_node(FheOp::InputGlwe1(a.clone()));
    let b_in = graph.add_node(FheOp::InputGlwe1(b.clone()));
    let cbs = graph.add_node(FheOp::CircuitBootstrap);
    let cmux = graph.add_node(FheOp::CMux);
    let o = graph.add_node(FheOp::OutputGlwe1(output.clone()));

    graph.add_edge(sel_in, cbs, FheEdge::Unary);
    graph.add_edge(cbs, cmux, FheEdge::Sel);
    graph.add_edge(a_in, cmux, FheEdge::Low);
    graph.add_edge(b_in, cmux, FheEdge::High);
    graph.add_edge(cmux, o, FheEdge::Unary);

    run_uop_program(&graph);

    assert_eq!(
        Polynomial::new(&vec![1; DEFAULT_128.l1_poly_degree().0]),
        enc.decrypt_glwe_l1(&AtomicRefCell::borrow(&output), &secret)
    );
}

#[test]
fn flow_control_still_allows_forward_progress() {
    let input = (0..256).map(|_| encrypt_lwe0(true)).collect::<Vec<_>>();
    let output = (0..256).map(|_| encrypt_lwe0(false)).collect::<Vec<_>>();

    let mut graph = FheCircuit::new();

    let input_nodes = input
        .iter()
        .map(|x| graph.add_node(FheOp::InputLwe0(x.clone())))
        .collect::<Vec<_>>();

    let output_nodes = output
        .iter()
        .map(|x| graph.add_node(FheOp::OutputLwe0(x.clone())))
        .collect::<Vec<_>>();

    for (i, o) in input_nodes.iter().zip(output_nodes.iter()) {
        graph.add_edge(*i, *o, FheEdge::Unary);
    }

    // Run this largish graph with restricted flow control and verify
    // it still completes.
    run_uop_program_with_fc_len(&graph, 1);

    for (i, o) in input.iter().zip(output.iter()) {
        assert_eq!(AtomicRefCell::borrow(i).0, AtomicRefCell::borrow(o).0,);
    }
}

#[test]
fn can_and() {
    let enc = get_encryption_128();
    let secret = get_secret_keys_128();

    let width = 4;

    let a_plaintext = [0, 1, 1, 0];
    let b_plaintext = [1, 0, 1, 0];

    let expected = a_plaintext.iter().zip(b_plaintext).map(|(x, y)| x & y);

    let a = a_plaintext.map(|x| encrypt_glwe1(&vec![x; DEFAULT_128.l1_poly_degree().0]));
    let b = b_plaintext.map(|x| encrypt_glwe1(&vec![x; DEFAULT_128.l1_poly_degree().0]));

    let mut graph = FheCircuit::new();
    let and_circuit = make_and_circuit(width as u16);

    // interleave c1 and c2 as required by the definition of the and circuit.
    let inputs = a
        .iter()
        .zip(b.iter())
        .flat_map(|(a, b)| vec![a.clone(), b.clone()])
        .collect::<Vec<_>>();

    let mut node_indices = vec![];
    for input in inputs {
        let i = graph.add_node(FheOp::InputGlwe1(input.clone()));
        let se = graph.add_node(FheOp::SampleExtract(0));
        graph.add_edge(i, se, crate::FheEdge::Unary);
        let ks = graph.add_node(FheOp::KeyswitchL1toL0);
        graph.add_edge(se, ks, crate::FheEdge::Unary);
        let cbs = graph.add_node(FheOp::CircuitBootstrap);
        graph.add_edge(ks, cbs, crate::FheEdge::Unary);
        node_indices.push(cbs);
    }

    let output = graph.insert_mux_circuit_l1glwe_outputs(&and_circuit, &node_indices, &enc);

    run_uop_program(&graph);

    for (exp, out) in expected.zip(output.iter()) {
        assert_eq!(
            exp,
            enc.decrypt_glwe_l1(&AtomicRefCell::borrow(&out.clone()), &secret)
                .coeffs()[0] as u64
        );
    }
}
