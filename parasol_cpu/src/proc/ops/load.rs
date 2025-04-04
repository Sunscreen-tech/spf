use std::sync::Arc;

use concurrency::AtomicRefCell;

use crate::{
    Ciphertext, CiphertextPtr, Error, FheProcessor, MemHazards, PtrRegister, Register, Result,
    proc::DispatchIsaOp,
    tomasulo::{
        registers::RobEntryRef, scoreboard::ScoreboardEntryRef, tomasulo_processor::RetirementInfo,
    },
    unwrap_registers,
};

use super::{check_offset, read_write_mask};

impl FheProcessor {
    #[allow(clippy::too_many_arguments)]
    /// Execute a load instruction.
    pub fn load(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        scoreboard_entry: ScoreboardEntryRef<DispatchIsaOp>,
        src: RobEntryRef<PtrRegister>,
        dst: RobEntryRef<Register>,
        width: u32,
        instruction_id: usize,
        pc: usize,
    ) {
        let load_impl = |scoreboard_entry: &ScoreboardEntryRef<DispatchIsaOp>| -> Result<()> {
            unwrap_registers!([self.constant_pool] (mut dst) (src));

            let num_bytes = width.next_multiple_of(8) as usize / 8;
            let mask = read_write_mask(width);

            match src {
                PtrRegister::Plaintext(ptr) => {
                    check_offset(width, ptr.offset, ptr.base.len(), instruction_id, pc)?;

                    // Plaintext loads and stores exec immediately, so we don't need to update our deps.

                    let mut result = 0u128;

                    for i in 0..(num_bytes - 1) {
                        result |= (*ptr.base[ptr.offset as usize + i].borrow() as u128) << (8 * i);
                    }

                    result |= ((mask & *ptr.base[ptr.offset as usize + num_bytes - 1].borrow())
                        as u128)
                        << (8 * (num_bytes - 1));

                    *dst = Register::Plaintext { val: result, width };

                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                PtrRegister::Ciphertext(CiphertextPtr::PlainOffset(ptr)) => {
                    check_offset(width, ptr.offset, ptr.base.len(), instruction_id, pc)?;
                    ptr.on_read(scoreboard_entry);

                    let result = (0..width)
                        .map(|_| Arc::new(AtomicRefCell::new(self.aux_data.enc.allocate_glwe_l1())))
                        .collect::<Vec<_>>();

                    let range = ptr.offset as usize * 8..ptr.offset as usize * 8 + width as usize;

                    for (input, output) in ptr.base[range].iter().zip(result.iter()) {
                        let input = AtomicRefCell::borrow(input);
                        let mut output = AtomicRefCell::borrow_mut(output);

                        output.clone_from(&input);
                    }

                    *dst = Register::Ciphertext(Ciphertext::L1Glwe { data: result });

                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                PtrRegister::Ciphertext(CiphertextPtr::EncOffset(ptr)) => {
                    ptr.on_read(scoreboard_entry);
                    todo!();
                }
                PtrRegister::Uninit => {
                    return Err(Error::AccessViolation {
                        inst_id: instruction_id,
                        pc,
                    });
                }
            };

            Ok(())
        };

        if let Err(e) = load_impl(&scoreboard_entry) {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
