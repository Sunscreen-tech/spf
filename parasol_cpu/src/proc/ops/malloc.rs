use std::sync::Arc;

use crate::{
    Error, Memory, Register, Result,
    proc::{DispatchIsaOp, fhe_processor::FheProcessor},
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

impl FheProcessor {
    pub fn malloc(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        memory: &Arc<Memory>,
        dst: RobEntryRef<Register>,
        size: RobEntryRef<Register>,
        instruction_id: usize,
        pc: u32,
    ) {
        let malloc_impl = || -> Result<()> {
            unwrap_registers!((mut dst) (size));

            match size {
                Register::Plaintext { val, width } => {
                    if *width != 32 || *val >= u32::MAX as u128 {
                        return Err(Error::IllegalOperands {
                            inst_id: instruction_id,
                            pc,
                        });
                    }

                    let ptr = memory.try_allocate(*val as u32)?;

                    *dst = Register::Plaintext {
                        val: ptr.0 as u128,
                        width: 32,
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

        if let Err(e) = malloc_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
