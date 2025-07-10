use crate::{
    DispatchIsaOp, Fault, Register,
    proc::fhe_processor::FheProcessor,
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

impl FheProcessor {
    pub fn dbg(
        &self,
        retirement_info: &RetirementInfo<DispatchIsaOp>,
        src: RobEntryRef<Register>,
        handler_id: u32,
        instruction_id: usize,
        pc: u32,
    ) {
        let handler_id = handler_id as usize;

        if self.debug_handlers.len() > handler_id {
            unwrap_registers!((src));

            self.debug_handlers[handler_id](instruction_id, pc, src);
        }

        FheProcessor::retire(retirement_info, Ok(()));
    }
}
