use mux_circuits::neg::negator;
use parasol_runtime::FheCircuit;

use crate::{
    Ciphertext, Error, Register, Result,
    proc::{DispatchIsaOp, fhe_processor::FheProcessor, ops::make_parent_op},
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

impl FheProcessor {
    /// Execute a load instruction.
    pub fn neg(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        src: RobEntryRef<Register>,
        _instruction_id: usize,
        _pc: u32,
    ) {
        let mut neg_impl = || -> Result<()> {
            unwrap_registers!((mut dst) (src));

            match src {
                Register::Plaintext { val, width } => {
                    let mask = (0x1 << width) - 1;

                    *dst = Register::Plaintext {
                        val: val.wrapping_neg() & mask,
                        width: *width,
                    };

                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                Register::Ciphertext(Ciphertext::L1Glwe { data: c }) => {
                    let mut graph = FheCircuit::new();

                    let neg_circuit = negator(c.len());

                    let output = graph.insert_mux_circuit_and_connect_inputs(
                        &neg_circuit,
                        c,
                        &self.aux_data.enc,
                    );

                    let parent_op = make_parent_op(&retirement_info);

                    self.aux_data
                        .uop_processor
                        .spawn_graph(&graph, &self.aux_data.flow, parent_op);

                    *dst = Register::Ciphertext(Ciphertext::L1Glwe { data: output });
                }
                _ => return Err(Error::EncryptionMismatch),
            };

            Ok(())
        };

        if let Err(e) = neg_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
