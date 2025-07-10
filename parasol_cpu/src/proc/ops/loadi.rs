use crate::{
    Error, Fault, Register, Result,
    proc::{DispatchIsaOp, fhe_processor::FheProcessor},
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

impl FheProcessor {
    pub fn loadi(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        imm: u32,
        width: u32,
        instruction_id: usize,
        pc: u32,
        fault: Fault,
    ) {
        let loadi_impl = || -> Result<()> {
            unwrap_registers!((mut dst));

            // check if the immediate number is out of range
            // a caveat that is LLVM will sign extend the immediate to 32 bit
            // if it's smaller than 32 bit, for example, in `ldi x10, -90, 8`
            // the number -90 in 2's complement with 8 bit will be 0xA6, but
            // in the encoding we have 32 bit for the immediate so it's
            // 0xFFFFFFA6, not 0x000000A6
            let in_range_unsigned = (imm as u64) < (1 << width);
            let in_range_signed_neg = imm >= 0xFFFFFFFF << (width - 1);

            if !in_range_unsigned && !in_range_signed_neg {
                return Err(Error::out_of_range(instruction_id, pc));
            }

            *dst = Register::Plaintext {
                val: imm as u128 & ((1 << width) - 1),
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
