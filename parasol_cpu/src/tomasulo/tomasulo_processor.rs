use std::{
    ops::{Deref, DerefMut},
    sync::{RwLockReadGuard, RwLockWriteGuard, mpsc::Sender},
};

use super::{registers::RobEntry, scoreboard::ScoreboardEntryRef};
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

pub trait SelectConstant<T> {
    fn select_constant_zero(&self) -> &T;
    fn select_constant_one(&self) -> &T;
}

pub enum InstructionOperation<I: Clone> {
    Retire(Result<ScoreboardEntryRef<I>>),
    Exec(ScoreboardEntryRef<I>),
}

pub enum RegRef<'a, T>
where
    T: Default,
{
    Read(RwLockReadGuard<'a, RobEntry<T>>),
    Write(RwLockWriteGuard<'a, RobEntry<T>>),
    Imm(&'a T),
}

impl<'a, T> From<RwLockReadGuard<'a, RobEntry<T>>> for RegRef<'a, T>
where
    T: Default,
{
    fn from(value: RwLockReadGuard<'a, RobEntry<T>>) -> Self {
        Self::Read(value)
    }
}

impl<'a, T> From<RwLockWriteGuard<'a, RobEntry<T>>> for RegRef<'a, T>
where
    T: Default,
{
    fn from(value: RwLockWriteGuard<'a, RobEntry<T>>) -> Self {
        Self::Write(value)
    }
}

impl<'a, T> From<&'a T> for RegRef<'a, T>
where
    T: Default,
{
    fn from(value: &'a T) -> Self {
        Self::Imm(value)
    }
}

impl<T> Deref for RegRef<'_, T>
where
    T: Default,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Imm(x) => x,
            Self::Read(x) => x,
            Self::Write(x) => x,
        }
    }
}

impl<T> DerefMut for RegRef<'_, T>
where
    T: Default,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Write(x) => x,
            _ => unreachable!("Cannot mutate immutable RegRef"),
        }
    }
}

/// An implementation detail of the [`impl_tomasulo`]` macro
#[macro_export]
macro_rules! impl_select_constant {
    ($ty:ident, $ct_ty:ident,$idx:tt) => {
        impl $crate::tomasulo::tomasulo_processor::SelectConstant<$ct_ty> for $ty {
            fn select_constant_zero(&self) -> &$ct_ty {
                &self.zero.$idx
            }

            fn select_constant_one(&self) -> &$ct_ty {
                &self.one.$idx
            }
        }
    };
}
