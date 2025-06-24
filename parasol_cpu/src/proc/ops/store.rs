use crate::{
    Byte, Error, Memory, Ptr32, Register, Result,
    proc::{DispatchIsaOp, fhe_processor::FheProcessor, ops::is_invalid_load_store_alignment},
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

impl FheProcessor {
    #[allow(clippy::too_many_arguments)]
    /// Execute a store instruction.
    pub fn store(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        memory: &Memory,
        src: RobEntryRef<Register>,
        dst: RobEntryRef<Register>,
        offset: i32,
        width: u32,
        instruction_id: usize,
        pc: u32,
    ) {
        let store_impl = || -> Result<()> {
            let mut dst = dst.entry_force_mut();
            let dst = &mut **dst;

            unwrap_registers!((src));

            match dst {
                Register::Plaintext { val: ptr, width: _ } => {
                    let base_addr = *ptr as u32;

                    let num_bytes = width / 8;

                    let base_addr = Ptr32::from(base_addr).try_signed_offset(offset)?;

                    if is_invalid_load_store_alignment(base_addr, num_bytes) {
                        return Err(Error::UnalignedAccess(base_addr.0));
                    }

                    for i in 0..num_bytes {
                        let byte = match src {
                            Register::Plaintext { val, width: _ } => {
                                Byte::from((val >> (8 * i)) as u8)
                            }
                            Register::Ciphertext(val) => {
                                let val = val.try_into_l1glwe()?;
                                let val = &val[8 * i as usize..8 * i as usize + 8];

                                Byte::try_from(val.to_owned()).unwrap()
                            }
                        };

                        // We've checked that our address is aligned, so overflow can't occur.
                        memory.try_store(base_addr.try_offset(i).unwrap(), byte)?;
                    }

                    FheProcessor::retire(&retirement_info, Ok(()));

                    Ok(())
                }
                _ => Err(Error::IllegalOperands {
                    inst_id: instruction_id,
                    pc,
                }),
            }
        };

        if let Err(e) = store_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
