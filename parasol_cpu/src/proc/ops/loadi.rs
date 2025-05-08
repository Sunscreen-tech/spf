use crate::{
    Error, Register, Result,
    proc::{DispatchIsaOp, fhe_processor::FheProcessor},
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

impl FheProcessor {
    pub fn loadi(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        imm: i32,
        width: u32,
        instruction_id: usize,
        pc: u32,
    ) {
        let loadi_impl = || -> Result<()> {
            unwrap_registers!((mut dst));

            // Sign extend imm
            let imm = imm as i128;

            // 2s complement features 1 more negative value than positive.
            // Hence the >= vs < mismatch.
            if (imm.is_positive() && imm >= 0x1 << (width - 1))
                || (imm.is_negative() && imm < -1 << (width - 1))
            {
                return Err(Error::out_of_range(instruction_id, pc));
            }

            // Bitcast imm from i128 to u128.
            *dst = Register::Plaintext {
                val: imm as u128,
                width,
            };

            FheProcessor::retire(&retirement_info, Ok(()));

            Ok(())
        };

        if let Err(e) = loadi_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
