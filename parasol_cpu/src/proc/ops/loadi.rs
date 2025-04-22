use crate::{
    Error, FheProcessor, Register, Result,
    proc::DispatchIsaOp,
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

impl FheProcessor {
    pub fn loadi(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        imm: u128,
        width: u32,
        instruction_id: usize,
        pc: usize,
    ) {
        let loadi_impl = || -> Result<()> {
            unwrap_registers!((mut dst));

            if imm >= 0x1 << width {
                return Err(Error::out_of_range(instruction_id, pc));
            }

            *dst = Register::Plaintext { val: imm, width };

            FheProcessor::retire(&retirement_info, Ok(()));

            Ok(())
        };

        if let Err(e) = loadi_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
