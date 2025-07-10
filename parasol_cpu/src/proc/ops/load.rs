use std::sync::{Arc, OnceLock};

use crate::{
    Byte, Ciphertext, Error, Memory, Ptr32, Register, Result,
    proc::{DispatchIsaOp, fhe_processor::FheProcessor, ops::is_invalid_load_store_alignment},
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

impl FheProcessor {
    #[allow(clippy::too_many_arguments)]
    /// Execute a load instruction.
    pub fn load(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        memory: &Memory,
        src: RobEntryRef<Register>,
        dst: RobEntryRef<Register>,
        offset: i32,
        width: u32,
        instruction_id: usize,
        pc: u32,
        fault: Arc<OnceLock<Error>>,
    ) {
        let load_impl = || -> Result<()> {
            unwrap_registers!((mut dst) (src));

            match src {
                Register::Plaintext { val: ptr, width: _ } => {
                    let num_bytes = width / 8;

                    let base_addr = Ptr32::from(*ptr as u32).try_signed_offset(offset)?;

                    if is_invalid_load_store_alignment(base_addr, num_bytes) {
                        return Err(Error::UnalignedAccess(base_addr.0));
                    }

                    // Load the first byte and check its type. Then, ensure each subsequent byte
                    // matches the same time.
                    match memory.try_load(base_addr)? {
                        Byte::Plaintext(val) => {
                            let mut result = val as u128;

                            for i in 1..num_bytes {
                                // We already checked alignment, so pointer can't overflow.
                                match memory.try_load(base_addr.try_offset(i).unwrap())? {
                                    Byte::Plaintext(b) => {
                                        result |= (b as u128) << (8 * i);
                                    }
                                    _ => {
                                        return Err(Error::buffer_not_a_plaintext());
                                    }
                                }
                            }

                            *dst = Register::Plaintext { val: result, width };
                        }
                        Byte::Ciphertext(val) => {
                            let mut result = val.clone();

                            for i in 1..num_bytes {
                                // We already checked alignment, so pointer can't overflow.
                                match memory.try_load(base_addr.try_offset(i).unwrap())? {
                                    Byte::Ciphertext(mut b) => {
                                        result.append(&mut b);
                                    }
                                    _ => {
                                        return Err(Error::buffer_not_a_ciphertext());
                                    }
                                }
                            }

                            *dst = Register::Ciphertext(Ciphertext::L1Glwe { data: result });
                        }
                    };

                    FheProcessor::retire(&retirement_info, Ok(()));
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

        if let Err(e) = load_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
