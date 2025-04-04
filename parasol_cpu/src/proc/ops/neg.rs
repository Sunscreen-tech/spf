use crate::{
    Ciphertext, FheProcessor, Register, Result,
    proc::DispatchIsaOp,
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
        _pc: usize,
    ) {
        let neg_impl = || -> Result<()> {
            unwrap_registers!([self.constant_pool] (mut dst) (src));

            match src {
                Register::Plaintext {
                    val: val1,
                    width: width1,
                } => {
                    let mask = (0x1 << width1) - 1;

                    *dst = Register::Plaintext {
                        val: val1.wrapping_neg() & mask,
                        width: *width1,
                    };

                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                Register::Ciphertext(Ciphertext::L1Glwe { data: _c1 }) => {
                    todo!()
                    // let output = add_l1glwe_cipher_cipher(c1, c2);

                    // *dst = Register::Ciphertext(Ciphertext::L1GlweCiphertext { data: output });
                }
                _ => {
                    todo!()
                }
            };

            Ok(())
        };

        if let Err(e) = neg_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
