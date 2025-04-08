use std::{
    ops::{Deref, DerefMut},
    sync::{mpsc::Sender, RwLockReadGuard, RwLockWriteGuard},
};

use parasol_runtime::{TrivialOne, TrivialZero};

use super::{registers::RobEntry, scoreboard::ScoreboardEntryRef};
use crate::Result;

/// An internal macro that generates an out-of-order executing processor with the given ISA.
#[macro_export]
macro_rules! impl_tomasulo {
    ($name:ident, $inst:ty,$dispatch:tt,[$(($reg_index:tt, $reg_type:ty, $reg_name:ident),)*]) => {
        paste::paste! {
            mod [<$name:snake _internal>] {
                use $crate::{
                    tomasulo::{
                        registers::{
                            RegisterFile,
                            RobEntryRef,
                        },
                        scoreboard::{
                            ScoreboardEntryId,
                            ScoreboardEntryRef,
                            ScoreboardEntry,
                        },
                        tomasulo_processor::{RegRef, Tomasulo, SelectConstant, RetirementInfo, InstructionOperation},
                    },
                    Result
                };

                use super::*;

                use log::trace;

                use std::sync::{
                    Arc,
                    atomic::{Ordering},
                    mpsc::{self, Sender, Receiver},
                };

                pub(crate) struct [<$name ConstantPool>] {
                    zero: ($($reg_type,)*),
                    one: ($($reg_type,)*)
                }

                impl [<$name ConstantPool>] {
                    pub fn new(enc: &Encryption) -> Self {
                        Self {
                            zero: ($($reg_type::trivial_zero(enc),)*),
                            one: ($($reg_type::trivial_one(enc),)*),
                        }
                    }

                    pub fn register<'a, T>(&'a self, reg_entry: &'a RobEntryRef<T>) -> RegRef<'a, T>
                    where
                        T: TrivialZero + TrivialOne,
                        Self: SelectConstant<T>,
                    {
                        use $crate::tomasulo::tomasulo_processor::SelectConstant;

                        match reg_entry {
                            RobEntryRef::Id(x) => x.entry().into(),
                            RobEntryRef::IdMut(x) => x.entry().into(),
                            RobEntryRef::Zero => self.select_constant_zero().into(),
                            RobEntryRef::One => self.select_constant_one().into(),
                        }
                    }

                    pub fn register_mut<'a, T>(&'a self, reg_entry: &'a RobEntryRef<T>) -> Result<RegRef<'a, T>>
                    where
                        T: TrivialZero + TrivialOne,
                        Self: $crate::tomasulo::tomasulo_processor::SelectConstant<T>,
                    {
                        match reg_entry {
                            RobEntryRef::IdMut(x) => Ok(x.entry_mut().into()),
                            _ => Err(Error::RegisterMutabilityViolation),
                        }
                    }

                    pub fn register_force_mut<'a, T>(&'a self, reg_entry: &'a RobEntryRef<T>) -> Result<RegRef<'a, T>>
                    where
                        T: TrivialZero + TrivialOne,
                        Self: $crate::tomasulo::tomasulo_processor::SelectConstant<T>,
                    {
                        match reg_entry {
                            RobEntryRef::IdMut(x) => Ok(x.entry_mut().into()),
                            RobEntryRef::Id(x) => Ok(x.entry_mut().into()),
                            _ => Err(Error::RegisterMutabilityViolation),
                        }
                    }
                }

                $($crate::impl_select_constant!{[<$name ConstantPool>], $reg_type, $reg_index})*

                pub(crate) struct $name where Self: Tomasulo {
                    /// The register file.
                    $($reg_name: RegisterFile<$reg_type, $dispatch>,)*

                    /// Extensible data specific to a particular
                    /// processor
                    pub aux_data: <Self as Tomasulo>::AuxiliaryData,

                    /// The set of values used for mapping constant
                    /// registers.
                    pub constant_pool: Arc<[<$name ConstantPool>]>,

                    /// The total number of instructions dispatched
                    current_instruction: usize,

                    /// The number of instructions currently dispatched or executing
                    pub instructions_inflight: usize,

                    /// Instructions ready for execution
                    pub ready_instructions: (
                        Sender<InstructionOperation<$dispatch>>,
                        Receiver<InstructionOperation<$dispatch>>
                    )
                }

                pub(crate) struct [<$name RegisterConfig>] {
                    $(pub [<$reg_name _num_registers>]: usize,)*
                }

                impl $name {
                    pub fn new(
                        enc: &Encryption,
                        register_config: &[<$name RegisterConfig>],
                        aux_data: <Self as Tomasulo>::AuxiliaryData,
                    ) -> Self {
                        $(let $reg_name = RegisterFile::<$reg_type, $dispatch>::new(register_config.[<$reg_name _num_registers>], enc);)*

                        Self {
                            $($reg_name,)*
                            aux_data,
                            constant_pool: Arc::new([<$name ConstantPool>]::new(enc)),
                            current_instruction: 0usize,
                            instructions_inflight: 0usize,
                            ready_instructions: mpsc::channel(),
                        }
                    }

                    pub fn dispatch_instruction(
                        &mut self,
                        inst: $inst,
                        pc: usize
                    ) -> Result<usize> {
                        use $crate::tomasulo::{ToDispatchedOp, GetDeps};

                        inst.validate(self.current_instruction, pc)?;

                        let srcs = (
                            $(&self. $reg_name,)* ()
                        );

                        // We need to capture the dependencies *before* we map our dispatch op.
                        // If we don't a src operand that's also a dst can get renamed and our
                        // deps traversal will be wrong.
                        let register_files = (
                            $(&self. [<$reg_name>],)* ()
                        );

                        let deps = inst.deps(register_files).collect::<Vec<_>>();

                        let scoreboard_entry = ScoreboardEntryRef::new(
                            &Arc::new(ScoreboardEntry::new(
                                ScoreboardEntryId::new(self.current_instruction),
                                pc
                            ))
                        );

                        let disp_inst = inst.to_dispatched_op(
                            srcs,
                            scoreboard_entry.clone(),
                            self.current_instruction,
                            pc
                        )?;

                        scoreboard_entry.set_instruction(&disp_inst);

                        self.current_instruction += 1;
                        self.instructions_inflight += 1;

                        // Increment our dependency count to 1 to prevent any dependents
                        // from issuing our new instruction until we've finished processing
                        // it.
                        scoreboard_entry.deps.fetch_add(1, Ordering::Acquire);

                        for dep in deps {
                            if let Some(dep) = dep {
                                // If we take a dependency on ourself, we somehow fucked up.
                                assert_ne!(dep.id, scoreboard_entry.id);
                                // If we're able to acquire the lock, then the dependency
                                // hasn't retired yet. Add ourselves as a dependant.
                                if let Some(mut deps) = dep.dependents.try_lock() {
                                    deps.push(scoreboard_entry.clone());
                                    scoreboard_entry.deps.fetch_add(1, Ordering::Acquire);
                                }
                            }
                        }

                        trace!("{}: Dispatched {}", stringify!($name), scoreboard_entry.id);

                        // Having processed our dependencies, decrement our count by 1
                        // to undo our initial increment and dispatch if all our
                        // dependencies are available.
                        if scoreboard_entry.deps.fetch_sub(1, Ordering::Release) == 1 {
                            self.ready_instructions.0.send(InstructionOperation::Exec(scoreboard_entry)).unwrap();
                        }

                        // Execute any ready instructions (possibly including the one we just dispatched)
                        self.execute_ready_instructions(false)?;

                        let next_pc = self.next_program_counter(disp_inst, pc)?;

                        Ok(next_pc)
                    }

                    fn execute_ready_instructions(&mut self, blocking: bool) -> Result<()> {

                        // Finally, attempt to execute any ready instructions
                        loop {
                            let ready = if blocking {
                                trace!("{}: Waiting for instructions", stringify!($name), );

                                // If no instructions remain, we're done.
                                if self.instructions_inflight == 0 {
                                    trace!("{}: No instructions remaining, finished", stringify!($name), );
                                    return Ok(());
                                }

                                self.ready_instructions.1.recv().unwrap()
                            } else {
                                let result = self.ready_instructions.1.try_recv();

                                match result {
                                    Ok(v) => v,
                                    // No instructions ready, return.
                                    Err(_) => { return Ok(()); }
                                }
                            };

                            trace!("{}: Instructions remaining {}", stringify!($name), self.instructions_inflight);

                            match ready {
                                InstructionOperation::Retire(Ok(v)) => {
                                    trace!("{}: Frontend retired {}", stringify!($name), v.id);

                                    self.instructions_inflight -= 1;
                                },
                                InstructionOperation::Retire(Err(e)) => {
                                    trace!("{}: Frontend received instruction failure {}", stringify!($name), e);

                                    return Err(e);
                                }
                                InstructionOperation::Exec(v) => {
                                    trace!("{}: Frontend executing {}", stringify!($name), v.id);

                                    self.exec_instruction(
                                        v.clone(),
                                        self.make_retirement_info(&v)
                                    );
                                },
                            }
                        };
                    }

                    fn make_retirement_info(&self, scoreboard_entry: &ScoreboardEntryRef<$dispatch>) -> RetirementInfo<$dispatch> {
                        RetirementInfo {
                            ready_instructions: self.ready_instructions.0.clone(),
                            scoreboard_entry: scoreboard_entry.clone(),
                        }
                    }

                    pub fn retire(
                        retirement_info: &RetirementInfo<$dispatch>,
                        result: Result<()>
                    ) {
                        if let Err(e) = result {
                            // Waiting thread may have dropped.
                            let _ = retirement_info.ready_instructions.send(InstructionOperation::Retire(Err(e)));
                            return;
                        }

                        let mut deps = retirement_info.scoreboard_entry.dependents.lock();

                        while let Some(dep) = deps.pop() {
                            let deps_remaining = dep.deps.fetch_sub(1, Ordering::Release);

                            if deps_remaining == 1 {
                                let _ = retirement_info.ready_instructions.send(InstructionOperation::Exec(dep));
                            }
                        }

                        // Throw away the lock handle as this instruction is retired.
                        // TODO: Is this a good idea on Mutex?
                        std::mem::forget(deps);

                        trace!("{}: Retired {}", stringify!($name), retirement_info.scoreboard_entry.id);

                        let _ = retirement_info.ready_instructions.send(InstructionOperation::Retire(Ok(retirement_info.scoreboard_entry.clone())));
                    }

                    /// Waits for all issued instructions to retire.
                    pub fn wait(&mut self) -> $crate::Result<()> {
                        self.execute_ready_instructions(true)?;

                        Ok(())
                    }
                }
            }

            pub(crate) use [<$name:snake _internal>]::*;
        }
    };
}

#[derive(Clone)]
pub struct RetirementInfo<I: Clone> {
    pub(crate) scoreboard_entry: ScoreboardEntryRef<I>,
    pub(crate) ready_instructions: Sender<InstructionOperation<I>>,
}

pub trait Tomasulo {
    type DispatchInstruction: Clone;
    type ConstantPool;
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
        pc: usize,
    ) -> Result<usize>;
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
    T: TrivialZero + TrivialOne,
{
    Read(RwLockReadGuard<'a, RobEntry<T>>),
    Write(RwLockWriteGuard<'a, RobEntry<T>>),
    Imm(&'a T),
}

impl<'a, T> From<RwLockReadGuard<'a, RobEntry<T>>> for RegRef<'a, T>
where
    T: TrivialZero + TrivialOne,
{
    fn from(value: RwLockReadGuard<'a, RobEntry<T>>) -> Self {
        Self::Read(value)
    }
}

impl<'a, T> From<RwLockWriteGuard<'a, RobEntry<T>>> for RegRef<'a, T>
where
    T: TrivialZero + TrivialOne,
{
    fn from(value: RwLockWriteGuard<'a, RobEntry<T>>) -> Self {
        Self::Write(value)
    }
}

impl<'a, T> From<&'a T> for RegRef<'a, T>
where
    T: TrivialZero + TrivialOne,
{
    fn from(value: &'a T) -> Self {
        Self::Imm(value)
    }
}

impl<T> Deref for RegRef<'_, T>
where
    T: TrivialZero + TrivialOne,
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
    T: TrivialZero + TrivialOne,
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
