use crate::{
    proc::DispatchIsaOp,
    tomasulo::{
        registers::RobEntryRef, scoreboard::ScoreboardEntryRef, tomasulo_processor::RetirementInfo,
    },
    unwrap_registers, CiphertextPtr, Error, FheProcessor, PlainOffsetCtPtr, PlaintextPtr,
    PtrRegister, Register, Result,
};

impl FheProcessor {
    #[allow(clippy::too_many_arguments)]
    pub fn cea(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        scoreboard_entry: ScoreboardEntryRef<DispatchIsaOp>,
        base: RobEntryRef<PtrRegister>,
        offset: RobEntryRef<Register>,
        dst: RobEntryRef<PtrRegister>,
        instruction_id: usize,
        pc: usize,
    ) {
        let cea_impl = |_scoreboard_entry: &ScoreboardEntryRef<DispatchIsaOp>| -> Result<()> {
            unwrap_registers!([self.constant_pool] (mut dst) (base) (offset));

            match (base, offset) {
                (
                    PtrRegister::Plaintext(base),
                    Register::Plaintext {
                        val: offset,
                        width: offset_width,
                    },
                ) => {
                    if *offset_width > 32 || *offset >= (0x1 << *offset_width) {
                        return Err(Error::out_of_range(instruction_id, pc));
                    }

                    // TODO: Sign extension
                    *dst = PtrRegister::Plaintext(PlaintextPtr {
                        base: base.base.clone(),
                        offset: base.offset.wrapping_add(*offset as u32),
                        last_write: base.last_write.clone(),
                    });

                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                (
                    PtrRegister::Ciphertext(CiphertextPtr::PlainOffset(x)),
                    Register::Plaintext {
                        val: offset,
                        width: offset_width,
                    },
                ) => {
                    if *offset_width > 32 || *offset >= (0x1 << *offset_width) {
                        return Err(Error::out_of_range(instruction_id, pc));
                    }

                    // TODO: Sign extension
                    *dst = PtrRegister::Ciphertext(CiphertextPtr::PlainOffset(PlainOffsetCtPtr {
                        base: x.base.clone(),
                        offset: x.offset.wrapping_add(*offset as u32),
                        last_write: x.last_write.clone(),
                    }));

                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                _ => {
                    todo!();
                }
            };

            Ok(())
        };

        if let Err(e) = cea_impl(&scoreboard_entry) {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
