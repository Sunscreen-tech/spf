use std::sync::Arc;

use parasol_concurrency::AtomicRefCell;
use parasol_runtime::{FheCircuit, FheEdge, FheOp};

use crate::{
    Ciphertext, Error, FheProcessor, Register, Result, check_register_width,
    proc::DispatchIsaOp,
    register_to_l1glwe_by_trivial_lift,
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

use super::make_parent_op;

impl FheProcessor {
    /// Execute an and instruction, where each element in the vector is a bit.
    #[allow(clippy::too_many_arguments)]
    pub fn cmux(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        select: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: usize,
    ) {
        let mut cmux_impl = || -> Result<()> {
            unwrap_registers!([self.constant_pool] (mut dst) (select) (a) (b));

            check_register_width(a, b, instruction_id, pc)?;

            // Assert that select is a single bit
            if select.width() != 1 {
                return Err(Error::WidthMismatch {
                    inst_id: instruction_id,
                    pc,
                });
            }

            if let Register::Plaintext { val, .. } = select {
                let decision = *val != 0;

                if let (
                    Register::Plaintext {
                        val: val_a,
                        width: _,
                    },
                    Register::Plaintext {
                        val: val_b,
                        width: _,
                    },
                ) = (a, b)
                {
                    *dst = Register::Plaintext {
                        val: if decision { *val_a } else { *val_b },
                        width: a.width() as u32,
                    }
                } else {
                    let ca = register_to_l1glwe_by_trivial_lift(
                        a,
                        &self.aux_data.l1glwe_zero,
                        &self.aux_data.l1glwe_one,
                    )?;

                    let cb = register_to_l1glwe_by_trivial_lift(
                        b,
                        &self.aux_data.l1glwe_zero,
                        &self.aux_data.l1glwe_one,
                    )?;

                    *dst = Register::Ciphertext(Ciphertext::L1Glwe {
                        data: if decision { ca } else { cb },
                    });
                }

                FheProcessor::retire(&retirement_info, Ok(()));

                return Ok(());
            }

            // For all other cases we have an encrypted selection bit so we need to
            // make a circuit.
            let ca = register_to_l1glwe_by_trivial_lift(
                a,
                &self.aux_data.l1glwe_zero,
                &self.aux_data.l1glwe_one,
            )?;

            let cb = register_to_l1glwe_by_trivial_lift(
                b,
                &self.aux_data.l1glwe_zero,
                &self.aux_data.l1glwe_one,
            )?;

            let width = a.width();

            let mut graph = FheCircuit::new();

            // Make a graph where it wires the input select into the FheOp::Cmux
            // operation. If the input select line is a is a glwe ciphertext,
            // first convert it to a ggsw ciphertext by circuit bootstrapping.
            // We know the data must be a single bit, so we can just take the
            // first element.
            let input_select = match select {
                Register::Ciphertext(Ciphertext::L1Glwe { data }) => {
                    let input_node = graph.add_node(FheOp::InputGlwe1(data[0].clone()));

                    let se = graph.add_node(FheOp::SampleExtract(0));
                    graph.add_edge(input_node, se, FheEdge::Unary);

                    let ks = graph.add_node(FheOp::KeyswitchL1toL0);
                    graph.add_edge(se, ks, FheEdge::Unary);

                    let cbs = graph.add_node(FheOp::CircuitBootstrap);
                    graph.add_edge(ks, cbs, FheEdge::Unary);

                    cbs
                }
                Register::Ciphertext(Ciphertext::L1Ggsw { data }) => {
                    let input_node = graph.add_node(FheOp::InputGgsw1(data[0].clone()));

                    let se = graph.add_node(FheOp::SampleExtract(0));
                    graph.add_edge(input_node, se, FheEdge::Unary);

                    se
                }
                _ => return Err(Error::RegisterCiphertextMismatch),
            };

            // Now use the input select to wire the input to the cmux operation.
            let output = (0..width)
                .map(|_| Arc::new(AtomicRefCell::new(self.aux_data.enc.allocate_glwe_l1())))
                .collect::<Vec<_>>();

            for (a, (b, o)) in ca.iter().zip(cb.iter().zip(output.iter())) {
                let a_node = graph.add_node(FheOp::InputGlwe1(a.clone()));
                let b_node = graph.add_node(FheOp::InputGlwe1(b.clone()));

                let cmux_output = graph.add_node(FheOp::CMux);

                graph.add_edge(input_select, cmux_output, FheEdge::Sel);
                graph.add_edge(a_node, cmux_output, FheEdge::High);
                graph.add_edge(b_node, cmux_output, FheEdge::Low);

                let out = graph.add_node(FheOp::OutputGlwe1(o.clone()));
                graph.add_edge(cmux_output, out, FheEdge::Unary);
            }

            let parent_op = make_parent_op(&retirement_info);

            self.aux_data
                .uop_processor
                .spawn_graph(&graph, &self.aux_data.flow, parent_op);

            *dst = Register::Ciphertext(Ciphertext::L1Glwe { data: output });

            Ok(())
        };

        if let Err(e) = cmux_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
