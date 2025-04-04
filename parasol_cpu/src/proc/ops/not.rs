use std::sync::Arc;

use concurrency::AtomicRefCell;
use parasol_runtime::{FheCircuit, FheEdge, FheOp};

use crate::{
    Ciphertext, Error, FheProcessor, Register, Result,
    proc::DispatchIsaOp,
    proc::ops::make_parent_op,
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

impl FheProcessor {
    /// Execute a load instruction.
    pub fn not(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        src: RobEntryRef<Register>,
        _instruction_id: usize,
        _pc: usize,
    ) {
        let mut add_impl = || -> Result<()> {
            unwrap_registers!([self.constant_pool] (mut dst) (src) );

            match src {
                Register::Plaintext { val, width } => {
                    let mask = (0x1 << width) - 1;

                    *dst = Register::Plaintext {
                        val: (!val) & mask,
                        width: *width,
                    };

                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                Register::Ciphertext(Ciphertext::L1Glwe { data: c }) => {
                    let width = c.len();

                    let mut graph = FheCircuit::new();

                    let dst_data = (0..width)
                        .map(|_| Arc::new(AtomicRefCell::new(self.aux_data.enc.allocate_glwe_l1())))
                        .collect::<Vec<_>>();

                    for (bit, dst) in c.iter().zip(dst_data.iter()) {
                        let bit_in_node = graph.add_node(FheOp::InputGlwe1(bit.clone()));
                        let neg_node = graph.add_node(FheOp::Not);
                        graph.add_edge(bit_in_node, neg_node, FheEdge::Unary);
                        let out = graph.add_node(FheOp::OutputGlwe1(dst.clone()));
                        graph.add_edge(neg_node, out, FheEdge::Unary);
                    }

                    let parent_op = make_parent_op(&retirement_info);

                    *dst = Register::Ciphertext(Ciphertext::L1Glwe { data: dst_data });

                    self.aux_data
                        .uop_processor
                        .spawn_graph(&graph, &self.aux_data.flow, parent_op);
                }
                _ => return Err(Error::RegisterCiphertextMismatch),
            };

            Ok(())
        };

        if let Err(e) = add_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
