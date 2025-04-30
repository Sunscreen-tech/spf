use std::sync::mpsc::Sender;

use super::scoreboard::ScoreboardEntryRef;
use crate::Result;

#[derive(Clone)]
pub struct RetirementInfo<I: Clone> {
    pub(crate) scoreboard_entry: ScoreboardEntryRef<I>,
    pub(crate) ready_instructions: Sender<InstructionOperation<I>>,
}

pub trait Tomasulo {
    type DispatchInstruction: Clone;
    type AuxiliaryData;

    /// Runs the given instruction.
    fn exec_instruction(
        &mut self,
        scoreboard_entry: ScoreboardEntryRef<Self::DispatchInstruction>,
        retirement_info: RetirementInfo<Self::DispatchInstruction>,
    );

    /// Runs the given instruction.
    fn next_program_counter(
        &mut self,
        dispatched_op: crate::proc::DispatchIsaOp,
        pc: u32,
    ) -> Result<u32>;
}

pub enum InstructionOperation<I: Clone> {
    Retire(Result<ScoreboardEntryRef<I>>),
    Exec(ScoreboardEntryRef<I>),
}
