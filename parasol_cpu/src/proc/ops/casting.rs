use std::sync::Arc;

use parasol_concurrency::AtomicRefCell;

use crate::{
    Ciphertext, Register, Result,
    proc::{DispatchIsaOp, fhe_processor::FheProcessor},
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

impl FheProcessor {
    /// Zero-extend the register `src` to the width `new_width` and store the
    /// result in `dst`.
    pub fn zext(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        src: RobEntryRef<Register>,
        new_width: u32,
        instruction_id: usize,
        pc: u32,
    ) {
        self.ext(
            retirement_info,
            dst,
            src,
            new_width,
            instruction_id,
            pc,
            false,
        )
    }

    pub fn sext(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        src: RobEntryRef<Register>,
        new_width: u32,
        instruction_id: usize,
        pc: u32,
    ) {
        self.ext(
            retirement_info,
            dst,
            src,
            new_width,
            instruction_id,
            pc,
            true,
        )
    }

    pub fn ext(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        src: RobEntryRef<Register>,
        new_width: u32,
        instruction_id: usize,
        pc: u32,
        signed: bool,
    ) {
        let ext_impl = || -> Result<()> {
            unwrap_registers!((mut dst) (src));

            if (new_width as usize) < src.width() {
                return Err(crate::Error::WidthMismatch {
                    inst_id: instruction_id,
                    pc,
                });
            }

            match src {
                Register::Plaintext { val, width } => {
                    *dst = Register::Plaintext {
                        val: if signed {
                            let sign_mask = 1 << (*width - 1);
                            if (sign_mask & *val) == 0 {
                                *val
                            } else {
                                let abs = (sign_mask << 1) - val;
                                (1 << new_width) - abs
                            }
                        } else {
                            *val
                        },
                        width: new_width,
                    };
                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                Register::Ciphertext(Ciphertext::L1Glwe { data }) => {
                    let current_width = data.len() as u32;

                    // Get trivial zeros
                    let pad = if signed {
                        data.last().unwrap().clone()
                    } else {
                        Arc::new(AtomicRefCell::new(self.aux_data.l1glwe_zero.clone()))
                    };

                    // We are little endian so we append zeros to the end
                    let output = data
                        .iter()
                        .chain(std::iter::repeat_n(
                            &pad,
                            (new_width - current_width) as usize,
                        ))
                        .cloned()
                        .collect();

                    *dst = Register::Ciphertext(Ciphertext::L1Glwe { data: output });

                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                // We expect the inputs to an instruction to either be plaintext
                // or L1 GLWE ciphertexts
                _ => {
                    return Err(crate::Error::EncryptionMismatch);
                }
            }

            Ok(())
        };

        if let Err(e) = ext_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }

    /// Truncate the register `src` to the width `new_width` and store the
    /// result in `dst`.
    pub fn trunc(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        src: RobEntryRef<Register>,
        new_width: u32,
        instruction_id: usize,
        pc: u32,
    ) {
        let trunc_impl = || -> Result<()> {
            unwrap_registers!((mut dst) (src));

            if (new_width as usize) > src.width() {
                return Err(crate::Error::WidthMismatch {
                    inst_id: instruction_id,
                    pc,
                });
            }

            match src {
                Register::Plaintext { val, width: _ } => {
                    let mask = (0x1 << new_width) - 1;
                    *dst = Register::Plaintext {
                        val: (*val) & mask,
                        width: new_width,
                    };

                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                Register::Ciphertext(Ciphertext::L1Glwe { data }) => {
                    // Little endian, we just take the first `new_width` elements
                    // let output = data.iter().take(new_width as usize).cloned().collect();
                    let output = data[0..new_width as usize].to_vec();

                    *dst = Register::Ciphertext(Ciphertext::L1Glwe { data: output });

                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                // We expect the inputs to an instruction to either be plaintext
                // or L1 GLWE ciphertexts
                _ => {
                    return Err(crate::Error::EncryptionMismatch);
                }
            }

            Ok(())
        };

        if let Err(e) = trunc_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
