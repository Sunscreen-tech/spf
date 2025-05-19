use crate::{
    Ciphertext, Register, Result,
    proc::{DispatchIsaOp, fhe_processor::FheProcessor},
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

impl FheProcessor {
    /// Execute a mov instruction
    pub fn mov(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        src: RobEntryRef<Register>,
    ) {
        let move_impl = || -> Result<()> {
            unwrap_registers!((mut dst) (src));

            match src {
                Register::Plaintext { val, width } => {
                    *dst = Register::Plaintext {
                        val: *val,
                        width: *width,
                    };
                }
                Register::Ciphertext(ciphertext) => {
                    *dst = Register::Ciphertext(match ciphertext {
                        Ciphertext::L0Lwe { data } => Ciphertext::L0Lwe { data: data.clone() },
                        Ciphertext::L1Lwe { data } => Ciphertext::L1Lwe { data: data.clone() },
                        Ciphertext::L1Glwe { data } => Ciphertext::L1Glwe { data: data.clone() },
                        Ciphertext::L1Ggsw { data } => Ciphertext::L1Ggsw { data: data.clone() },
                    });
                }
            };

            FheProcessor::retire(&retirement_info, Ok(()));

            Ok(())
        };

        if let Err(e) = move_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
