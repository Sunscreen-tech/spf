use std::sync::Arc;

use parasol_concurrency::AtomicRefCell;

use crate::{
    FheCircuit, FheEdge, FheOp,
    test_utils::{get_encryption_128, make_uproc_128},
};

#[test]
fn wrong_inputs_none_expected() {
    let enc = get_encryption_128();
    let (proc, fc) = make_uproc_128();

    let zero_inputs = [
        FheOp::InputLwe0(Arc::new(AtomicRefCell::new(enc.allocate_lwe_l0()))),
        FheOp::InputLwe1(Arc::new(AtomicRefCell::new(enc.allocate_lwe_l1()))),
        FheOp::InputGlwe1(Arc::new(AtomicRefCell::new(enc.allocate_glwe_l1()))),
        FheOp::InputGgsw1(Arc::new(AtomicRefCell::new(enc.allocate_ggsw_l1()))),
        FheOp::InputGlev1(Arc::new(AtomicRefCell::new(enc.allocate_glev_l1()))),
        FheOp::ZeroLwe0,
        FheOp::OneLwe0,
        FheOp::ZeroGlwe1,
        FheOp::OneGlwe1,
        FheOp::ZeroGgsw1,
        FheOp::OneGgsw1,
        FheOp::ZeroGlev1,
        FheOp::OneGlev1,
        FheOp::Nop,
    ];

    for n in zero_inputs {
        let mut graph = FheCircuit::new();
        let a = graph.add_node(FheOp::ZeroLwe0);
        let b = graph.add_node(n);
        graph.add_edge(a, b, crate::FheEdge::Unary);

        let result = proc.lock().unwrap().run_graph_blocking(&graph, &fc);

        assert!(result.is_err());
    }
}

#[test]
fn wrong_inputs_some_expected() {
    let enc = get_encryption_128();
    let (proc, fc) = make_uproc_128();

    let one_inputs = [
        FheOp::OutputLwe0(Arc::new(AtomicRefCell::new(enc.allocate_lwe_l0()))),
        FheOp::OutputLwe1(Arc::new(AtomicRefCell::new(enc.allocate_lwe_l1()))),
        FheOp::OutputGlwe1(Arc::new(AtomicRefCell::new(enc.allocate_glwe_l1()))),
        FheOp::OutputGgsw1(Arc::new(AtomicRefCell::new(enc.allocate_ggsw_l1()))),
        FheOp::OutputGlev1(Arc::new(AtomicRefCell::new(enc.allocate_glev_l1()))),
        FheOp::SampleExtract(1),
        FheOp::KeyswitchL1toL0,
        FheOp::Not,
        FheOp::CircuitBootstrap,
        FheOp::SchemeSwitch,
        FheOp::MulXN(5),
        FheOp::CMux,
        FheOp::GlevCMux,
        FheOp::MultiplyGgswGlwe,
        FheOp::GlweAdd,
    ];

    for n in one_inputs {
        let mut graph = FheCircuit::new();
        graph.add_node(n);

        let result = proc.lock().unwrap().run_graph_blocking(&graph, &fc);

        assert!(result.is_err());
    }
}

#[test]
fn illegal_sample_extract() {
    let (proc, fc) = make_uproc_128();

    let mut graph = FheCircuit::new();
    let a = graph.add_node(FheOp::ZeroLwe0);
    let b = graph.add_node(FheOp::SampleExtract(2048));
    graph.add_edge(a, b, FheEdge::Unary);

    let result = proc.lock().unwrap().run_graph_blocking(&graph, &fc);

    assert!(result.is_err());
}

#[test]
fn missing_input() {
    let enc = get_encryption_128();
    let (proc, fc) = make_uproc_128();

    let mut graph = FheCircuit::new();
    let a = graph.add_node(FheOp::OutputGlwe1(Arc::new(AtomicRefCell::new(
        enc.allocate_glwe_l1(),
    ))));
    let b = graph.add_node(FheOp::SampleExtract(5));
    graph.add_edge(a, b, FheEdge::Unary);

    let result = proc.lock().unwrap().run_graph_blocking(&graph, &fc);

    assert!(result.is_err());
}

#[test]
fn illegal_retire_op() {
    let (proc, fc) = make_uproc_128();

    let mut graph = FheCircuit::new();
    graph.add_node(FheOp::Retire);

    let result = proc.lock().unwrap().run_graph_blocking(&graph, &fc);

    assert!(result.is_err());
}
