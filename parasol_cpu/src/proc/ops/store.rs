use std::ops::DerefMut;

use parasol_concurrency::AtomicRefCell;

use crate::{
    CiphertextPtr, Error, FheProcessor, MemHazards, PtrRegister, Register, Result,
    proc::DispatchIsaOp,
    tomasulo::{
        registers::RobEntryRef, scoreboard::ScoreboardEntryRef, tomasulo_processor::RetirementInfo,
    },
    unwrap_registers,
};

use super::{check_offset, read_write_mask};

impl FheProcessor {
    #[allow(clippy::too_many_arguments)]
    /// Execute a store instruction.
    pub fn store(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        scoreboard_entry: ScoreboardEntryRef<DispatchIsaOp>,
        src: RobEntryRef<Register>,
        dst: RobEntryRef<PtrRegister>,
        width: u32,
        instruction_id: usize,
        pc: usize,
    ) {
        let store_impl = |scoreboard_entry: &ScoreboardEntryRef<DispatchIsaOp>| -> Result<()> {
            let mut dst = dst.entry_force_mut();
            let dst: &mut PtrRegister = dst.deref_mut();

            unwrap_registers!((src));

            let mask = read_write_mask(width);
            let num_bytes = width.next_multiple_of(8) as usize / 8;

            match (src, &mut *dst) {
                (
                    Register::Plaintext {
                        val,
                        width: reg_width,
                    },
                    PtrRegister::Plaintext(ptr),
                ) => {
                    check_offset(width, ptr.offset, ptr.base.len(), instruction_id, pc)?;

                    if *reg_width != width {
                        return Err(Error::WidthMismatch {
                            inst_id: instruction_id,
                            pc,
                        });
                    }

                    // Plaintext loads and stores exec immediately, so we don't need to update our deps.

                    for i in 0..(num_bytes - 1) {
                        let shift_amt = 8 * i;
                        *ptr.base[i].borrow_mut() = (val >> shift_amt) as u8;
                    }

                    let shift_amt = 8 * (num_bytes - 1);
                    *ptr.base[num_bytes - 1].borrow_mut() = mask & (val >> shift_amt) as u8;

                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                (
                    Register::Ciphertext(val),
                    PtrRegister::Ciphertext(CiphertextPtr::PlainOffset(ptr)),
                ) => {
                    check_offset(width, ptr.offset, ptr.base.len(), instruction_id, pc)?;

                    if val.len() != width as usize {
                        return Err(Error::WidthMismatch {
                            inst_id: instruction_id,
                            pc,
                        });
                    }

                    ptr.on_write(scoreboard_entry);

                    let range = 8 * ptr.offset as usize..8 * ptr.offset as usize + width as usize;

                    for (input, output) in val.try_into_l1glwe()?.iter().zip(ptr.base[range].iter())
                    {
                        let input = AtomicRefCell::borrow(input);
                        let mut output = AtomicRefCell::borrow_mut(output);

                        output.clone_from(&input);
                    }

                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                (
                    Register::Ciphertext(_val),
                    PtrRegister::Ciphertext(CiphertextPtr::EncOffset(ptr)),
                ) => {
                    ptr.on_write(scoreboard_entry);

                    todo!();
                }
                (_, PtrRegister::Uninit) => {
                    return Err(Error::AccessViolation(0));
                }
                _ => {
                    return Err(Error::IllegalOperands {
                        inst_id: instruction_id,
                        pc,
                    });
                }
            };

            Ok(())
        };

        if let Err(e) = store_impl(&scoreboard_entry) {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
