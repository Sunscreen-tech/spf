use mux_circuits::and::make_and_circuit;
use parasol_runtime::{FheCircuit, FheEdge, FheOp};

use crate::{
    check_register_width,
    proc::DispatchIsaOp,
    register_to_l1glwe_by_trivial_lift,
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers, Ciphertext, FheProcessor, Register, Result,
};

use super::make_parent_op;

impl FheProcessor {
    /// Execute an and instruction, where each element in the vector is a bit.
    pub fn and(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: usize,
    ) {
        let mut and_impl = || -> Result<()> {
            unwrap_registers!([self.constant_pool] (mut dst) (a) (b));

            check_register_width(a, b, instruction_id, pc)?;

            if let (
                Register::Plaintext { val: val1, width },
                Register::Plaintext {
                    val: val2,
                    width: _,
                },
            ) = (a, b)
            {
                let mask = (0x1 << width) - 1;

                *dst = Register::Plaintext {
                    val: val1 & val2 & mask,
                    width: *width,
                };

                FheProcessor::retire(&retirement_info, Ok(()));
            } else {
                let c1 = register_to_l1glwe_by_trivial_lift(
                    a,
                    &self.aux_data.l1glwe_zero,
                    &self.aux_data.l1glwe_one,
                )?;

                let c2 = register_to_l1glwe_by_trivial_lift(
                    b,
                    &self.aux_data.l1glwe_zero,
                    &self.aux_data.l1glwe_one,
                )?;

                let width = a.width();

                let mut graph = FheCircuit::new();
                let and_circuit = make_and_circuit(width as u16);

                // interleave c1 and c2 as required by the definition of the and circuit.
                let inputs = c1
                    .iter()
                    .zip(c2.iter())
                    .flat_map(|(a, b)| vec![a.clone(), b.clone()])
                    .collect::<Vec<_>>();

                let mut node_indices = vec![];
                for input in inputs {
                    let i = graph.add_node(FheOp::InputGlwe1(input.clone()));
                    let se = graph.add_node(FheOp::SampleExtract(0));
                    graph.add_edge(i, se, FheEdge::Unary);
                    let ks = graph.add_node(FheOp::KeyswitchL1toL0);
                    graph.add_edge(se, ks, FheEdge::Unary);
                    let cbs = graph.add_node(FheOp::CircuitBootstrap);
                    graph.add_edge(ks, cbs, FheEdge::Unary);
                    node_indices.push(cbs);
                }

                let output = graph.insert_mux_circuit_l1glwe_outputs(
                    &and_circuit,
                    &node_indices,
                    &self.aux_data.enc,
                );

                let parent_op = make_parent_op(&retirement_info);

                self.aux_data
                    .uop_processor
                    .spawn_graph(&graph, &self.aux_data.flow, parent_op);

                *dst = Register::Ciphertext(Ciphertext::L1Glwe { data: output });
            }

            Ok(())
        };

        if let Err(e) = and_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
