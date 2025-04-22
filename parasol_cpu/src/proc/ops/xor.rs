use std::sync::Arc;

use parasol_concurrency::AtomicRefCell;
use parasol_runtime::{FheCircuit, FheEdge, FheOp};

use crate::{
    Ciphertext, FheProcessor, Register, Result, check_register_width,
    proc::DispatchIsaOp,
    proc::ops::make_parent_op,
    register_to_l1glwe_by_trivial_lift,
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

impl FheProcessor {
    /// Execute a load instruction.
    pub fn xor(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: usize,
    ) {
        let mut xor_impl = || -> Result<()> {
            unwrap_registers!((mut dst) (a) (b) );

            check_register_width(a, b, instruction_id, pc)?;

            if let (
                Register::Plaintext {
                    val: val1,
                    width: width1,
                },
                Register::Plaintext {
                    val: val2,
                    width: _,
                },
            ) = (a, b)
            {
                let mask = (0x1 << width1) - 1;

                *dst = Register::Plaintext {
                    val: val1 ^ val2 & mask,
                    width: *width1,
                };

                FheProcessor::retire(&retirement_info, Ok(()));
            } else {
                let width = a.width();

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

                let mut graph = FheCircuit::new();
                let dst_data = (0..width)
                    .map(|_| Arc::new(AtomicRefCell::new(self.aux_data.enc.allocate_glwe_l1())))
                    .collect::<Vec<_>>();

                for (bit_a, (bit_b, dst)) in c1.iter().zip(c2.iter().zip(dst_data.iter())) {
                    let bit_a_in_node = graph.add_node(FheOp::InputGlwe1(bit_a.clone()));
                    let bit_b_in_node = graph.add_node(FheOp::InputGlwe1(bit_b.clone()));
                    let xor_node = graph.add_node(FheOp::GlweAdd);
                    graph.add_edge(bit_a_in_node, xor_node, FheEdge::Left);
                    graph.add_edge(bit_b_in_node, xor_node, FheEdge::Right);
                    let out = graph.add_node(FheOp::OutputGlwe1(dst.clone()));
                    graph.add_edge(xor_node, out, FheEdge::Unary);
                }

                let parent_op = make_parent_op(&retirement_info);

                *dst = Register::Ciphertext(Ciphertext::L1Glwe { data: dst_data });

                self.aux_data
                    .uop_processor
                    .spawn_graph(&graph, &self.aux_data.flow, parent_op);
            }

            Ok(())
        };

        if let Err(e) = xor_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
