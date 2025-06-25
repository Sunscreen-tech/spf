use crate::{
    Byte, INSTRUCTION_SIZE, Memory, Result,
    register_names::*,
    tomasulo::{
        registers::{RegisterFile, RegisterName, RobEntryRef},
        scoreboard::{ScoreboardEntry, ScoreboardEntryId, ScoreboardEntryRef},
        tomasulo_processor::{InstructionOperation, RetirementInfo, Tomasulo},
    },
    unwrap_registers,
};

use super::{ops::is_invalid_load_store_alignment, *};

use log::{debug, error, trace};

use std::sync::{
    Arc,
    atomic::Ordering,
    mpsc::{self, Receiver, Sender},
};

type DebugHandler = Arc<dyn Fn(usize, u32, &Register) + Send + Sync + 'static>;

/// Options for running [`FheComputer::run_program_with_options`]
#[derive(Clone, Default)]
pub struct RunProgramOptions {
    gas_limit: Option<u32>,
    log_instruction_execution: bool,
    log_register_info: bool,
    debug_handlers: Vec<DebugHandler>,
}

impl RunProgramOptions {
    /// Creates a new [`RunProgramOptions`]
    pub fn new() -> Self {
        Self::default()
    }

    /// Gas limit for a program before it terminates
    pub fn gas_limit(&self) -> Option<u32> {
        self.gas_limit
    }
}

/// Builder pattern for [`RunProgramOptions`]
#[derive(Default)]
pub struct RunProgramOptionsBuilder {
    gas_limit: Option<u32>,
    log_instruction_execution: bool,
    log_register_info: bool,
    debug_handlers: Vec<DebugHandler>,
}

impl RunProgramOptionsBuilder {
    /// Creates a new [`RunProgramOptionsBuilder`]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the gas limit.
    pub fn gas_limit(mut self, gas_limit: Option<u32>) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    /// Enable debug logging for instruction decode, execution, and retirement.
    ///
    /// # Remarks
    /// These logs will be emitted with `log::debug!`. You'll need an appropriate
    /// logger installed to see them (e.g. `env_logger`).
    pub fn log_instruction_execution(mut self, val: bool) -> Self {
        self.log_instruction_execution = val;
        self
    }

    /// Dump the register state before decoding each instruction.
    ///
    /// # Remarks
    /// These logs will be emitted with `log::debug!`. You'll need an appropriate
    /// logger installed to see them (e.g. `env_logger`).
    pub fn log_register_info(mut self, val: bool) -> Self {
        self.log_register_info = val;
        self
    }

    /// Install a debug handler that gets invoked on hitting a `Dbg` instruction.
    pub fn debug_handler<F: Fn(usize, u32, &Register) + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.debug_handlers.push(Arc::new(f));
        self
    }

    /// Build the run program options into a [`RunProgramOptions`] struct.
    pub fn build(self) -> RunProgramOptions {
        RunProgramOptions {
            gas_limit: self.gas_limit,
            log_instruction_execution: self.log_instruction_execution,
            log_register_info: self.log_register_info,
            debug_handlers: self.debug_handlers,
        }
    }
}

pub(crate) struct FheProcessor
where
    Self: Tomasulo,
{
    /// The register file.
    registers: RegisterFile<Register, DispatchIsaOp>,

    /// Extensible data specific to a particular
    /// processor
    pub aux_data: <Self as Tomasulo>::AuxiliaryData,

    /// The total number of instructions dispatched
    current_instruction: usize,

    pc: u32,

    /// The number of instructions currently dispatched or executing
    pub instructions_inflight: usize,

    /// Instructions ready for execution
    pub ready_instructions: (
        Sender<InstructionOperation<DispatchIsaOp>>,
        Receiver<InstructionOperation<DispatchIsaOp>>,
    ),

    pub debug_handlers: Vec<DebugHandler>,
}

impl FheProcessor {
    pub fn new(aux_data: <Self as Tomasulo>::AuxiliaryData) -> Self {
        let registers = RegisterFile::<Register, DispatchIsaOp>::new(64);

        Self {
            registers,
            aux_data,
            pc: 0,
            current_instruction: 0,
            instructions_inflight: 0,
            ready_instructions: mpsc::channel(),
            debug_handlers: vec![],
        }
    }

    // This method requires that load and store operations have no in-flight
    // register dependencies. That is, its src/dst register value must be resolved before we decode
    // this instruction.
    //
    // Removing this assumption requires multiple stages of dependency checking, as we will need this
    // if we allow encrypted load/store src/dst registers.
    fn try_append_memory_dependencies(
        &mut self,
        deps: &mut Vec<Option<ScoreboardEntryRef<DispatchIsaOp>>>,
        scoreboard_entry: &ScoreboardEntryRef<DispatchIsaOp>,
        inst_id: usize,
        pc: u32,
    ) -> Result<()> {
        // Decode the current instruction's memory read/write address, look for any in-flight
        // read/writes to the same address and take dependencies on them.
        //
        // If none exist, then this instruction has no memory dependencies and is free to execute
        // immediately.
        let mut update_memory_deps = |reg: &Register, width: u32, offset: i32| {
            // Add any existing load/store operations to the same addresses this operation touches
            // as dependencies.
            match reg {
                Register::Plaintext { val: ptr, width: _ } => {
                    let base_addr = *ptr as u32;

                    let num_bytes = width / 8;

                    let base_addr = Ptr32::from(base_addr).try_signed_offset(offset)?;

                    if is_invalid_load_store_alignment(base_addr, num_bytes) {
                        return Err(Error::UnalignedAccess(base_addr.0));
                    }

                    for i in 0..num_bytes {
                        let ptr = base_addr.try_offset(i).unwrap();

                        if let Some(dep) = self.aux_data.inflight_memory_ops.get(&ptr) {
                            deps.push(Some(dep.clone()));
                        }

                        // Mark this instruction as the most recent reader/writer to this address.
                        // This adds false RAR dependencies when reading from the same address, but
                        // whatever.
                        self.aux_data
                            .inflight_memory_ops
                            .insert(ptr, scoreboard_entry.clone());
                    }
                }
                _ => return Err(Error::IllegalOperands { inst_id, pc }),
            };

            Ok(())
        };

        match &scoreboard_entry.instruction.borrow().as_ref().unwrap() {
            DispatchIsaOp::Store(dst, _, width, offset) => {
                unwrap_registers!((dst));

                update_memory_deps(dst, *width, *offset)?
            }
            DispatchIsaOp::Load(_, src, width, offset) => {
                unwrap_registers!((src));

                update_memory_deps(src, *width, *offset)?
            }
            _ => {}
        };

        Ok(())
    }

    /// Figures out the gas cost for the given instruction
    fn compute_gas(&self, dispatched_op: &crate::proc::DispatchIsaOp) -> u32 {
        fn is_register_ciphertext(reg: &RobEntryRef<Register>) -> bool {
            match reg {
                RobEntryRef::Id(e) | RobEntryRef::IdMut(e) => e.entry().is_ciphertext(),
            }
        }

        use DispatchIsaOp::*;

        match dispatched_op {
            // instructions that do not compute anything are assigned trivial gas cost
            Load(..) | LoadI(..) | Store(..) | BranchNonZero(..) | BranchZero(..) | Branch(..)
            | Move(..) | Dbg(..) => 1,

            // instructions that compute on one input source, but gas does not rely on it
            Sext(..) | Zext(..) | Trunc(..) => 1,

            // instructions that compute on one input source
            Not(_, input) | Neg(_, input) => {
                if is_register_ciphertext(input) {
                    100_000
                } else {
                    1
                }
            }

            // instructions that compute on two input sources that are interchangeable, and gas relies on either of them
            And(_, input1, input2)
            | Or(_, input1, input2)
            | Xor(_, input1, input2)
            | Add(_, input1, input2)
            | Sub(_, input1, input2)
            | CmpEq(_, input1, input2)
            | CmpGt(_, input1, input2)
            | CmpGe(_, input1, input2)
            | CmpLt(_, input1, input2)
            | CmpLe(_, input1, input2)
            | CmpGtS(_, input1, input2)
            | CmpGeS(_, input1, input2)
            | CmpLtS(_, input1, input2)
            | CmpLeS(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    100_000
                } else {
                    1
                }
            }

            Mul(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    500_000
                } else {
                    1
                }
            }

            // instructions that compute on two input sources that are not interchangeable, and gas relies on only one of them
            Shr(_, _, input)
            | Shra(_, _, input)
            | Shl(_, _, input)
            | Rotr(_, _, input)
            | Rotl(_, _, input) => {
                if is_register_ciphertext(input) {
                    100_000
                } else {
                    1
                }
            }

            // instructions that compute on three input sources that are interchangeable, and gas relies on either of them
            AddC(_, _, input1, input2, input3)
            | SubB(_, _, input1, input2, input3)
            | Cmux(_, input1, input2, input3) => {
                if is_register_ciphertext(input1)
                    || is_register_ciphertext(input2)
                    || is_register_ciphertext(input3)
                {
                    100_000
                } else {
                    1
                }
            }

            // return has zero gas cost
            Ret() => 0,
        }
    }

    pub fn dispatch_instruction(
        &mut self,
        inst: IsaOp,
        pc: u32,
        options: &RunProgramOptions,
    ) -> Result<(u32, u32)> {
        use crate::tomasulo::{GetDeps, ToDispatchedOp};

        inst.validate(self.current_instruction, pc)?;

        let srcs = (&self.registers, ());

        if options.log_instruction_execution {
            debug!(
                "Dispatching pc={pc} id={} {:?}",
                self.current_instruction, inst
            );
        }

        if options.log_register_info {
            self.registers.trace_dump();
        }

        // We need to capture the dependencies *before* we map our dispatch op.
        // If we don't a src operand that's also a dst can get renamed and our
        // deps traversal will be wrong.
        let mut deps = inst.deps(srcs).collect::<Vec<_>>();

        let scoreboard_entry = ScoreboardEntryRef::new(&Arc::new(ScoreboardEntry::new(
            ScoreboardEntryId::new(self.current_instruction),
            pc,
        )));

        let disp_inst =
            inst.to_dispatched_op(srcs, scoreboard_entry.clone(), self.current_instruction, pc)?;

        let gas = self.compute_gas(&disp_inst);

        if let Some(gas_limit) = options.gas_limit {
            if gas > gas_limit {
                return Err(Error::OutOfGas(gas, gas_limit));
            }
        }

        scoreboard_entry.set_instruction(&disp_inst);

        self.current_instruction += 1;
        self.instructions_inflight += 1;

        // Increment our dependency count to 1 to prevent any dependents
        // from issuing our new instruction until we've finished processing
        // it.
        scoreboard_entry.deps.fetch_add(1, Ordering::Acquire);

        // For load/store instructions, add any memory instruction dependencies to ensure
        // read/writes happen in the correct order.
        self.try_append_memory_dependencies(
            &mut deps,
            &scoreboard_entry,
            self.current_instruction,
            pc,
        )?;

        for dep in deps.into_iter().flatten() {
            // If we take a dependency on ourself, we somehow fucked up.
            assert_ne!(dep.id, scoreboard_entry.id);
            // If we're able to acquire the lock, then the dependency
            // hasn't retired yet. Add ourselves as a dependant.
            if let Some(mut deps) = dep.dependents.try_lock() {
                deps.push(scoreboard_entry.clone());
                scoreboard_entry.deps.fetch_add(1, Ordering::Acquire);
            }
        }

        trace!("{}: Dispatched {}", stringify!($name), scoreboard_entry.id);

        // Having processed our dependencies, decrement our count by 1
        // to undo our initial increment and dispatch if all our
        // dependencies are available.
        if scoreboard_entry.deps.fetch_sub(1, Ordering::Release) == 1 {
            self.ready_instructions
                .0
                .send(InstructionOperation::Exec(scoreboard_entry))
                .unwrap();
        }

        // Execute any ready instructions (possibly including the one we just dispatched)
        self.execute_ready_instructions(false, options)?;

        let next_pc = self.next_program_counter(disp_inst, pc)?;

        Ok((next_pc, gas))
    }

    fn execute_ready_instructions(
        &mut self,
        blocking: bool,
        options: &RunProgramOptions,
    ) -> Result<()> {
        // Finally, attempt to execute any ready instructions
        loop {
            let ready = if blocking {
                if options.log_instruction_execution {
                    trace!("Waiting for instructions");
                }

                // If no instructions remain, we're done.
                if self.instructions_inflight == 0 {
                    if options.log_instruction_execution {
                        trace!("No instructions remaining, finished");
                    }
                    return Ok(());
                }

                self.ready_instructions.1.recv().unwrap()
            } else {
                let result = self.ready_instructions.1.try_recv();

                match result {
                    Ok(v) => v,
                    // No instructions ready, return.
                    Err(_) => {
                        return Ok(());
                    }
                }
            };

            if options.log_instruction_execution {
                trace!("Instructions remaining {}", self.instructions_inflight);
            }

            match ready {
                InstructionOperation::Retire(Ok(v)) => {
                    if options.log_instruction_execution {
                        debug!("retired id={} pc={}", v.id, v.pc);
                    }

                    self.instructions_inflight -= 1;
                }
                InstructionOperation::Retire(Err(e)) => {
                    error!("retire error e={e}");

                    return Err(e);
                }
                InstructionOperation::Exec(v) => {
                    self.exec_instruction(v.clone(), self.make_retirement_info(&v), options);
                }
            }
        }
    }

    fn make_retirement_info(
        &self,
        scoreboard_entry: &ScoreboardEntryRef<DispatchIsaOp>,
    ) -> RetirementInfo<DispatchIsaOp> {
        RetirementInfo {
            ready_instructions: self.ready_instructions.0.clone(),
            scoreboard_entry: scoreboard_entry.clone(),
        }
    }

    pub fn retire(retirement_info: &RetirementInfo<DispatchIsaOp>, result: Result<()>) {
        if let Err(e) = result {
            // Waiting thread may have dropped.
            let _ = retirement_info
                .ready_instructions
                .send(InstructionOperation::Retire(Err(e)));
            return;
        }

        let mut deps = retirement_info.scoreboard_entry.dependents.lock();

        while let Some(dep) = deps.pop() {
            let deps_remaining = dep.deps.fetch_sub(1, Ordering::Release);

            if deps_remaining == 1 {
                let _ = retirement_info
                    .ready_instructions
                    .send(InstructionOperation::Exec(dep));
            }
        }

        // Throw away the lock handle as this instruction is retired.
        // TODO: Is this a good idea on Mutex?
        std::mem::forget(deps);

        trace!(
            "{}: Retired {}",
            stringify!($name),
            retirement_info.scoreboard_entry.id
        );

        let _ = retirement_info
            .ready_instructions
            .send(InstructionOperation::Retire(Ok(retirement_info
                .scoreboard_entry
                .clone())));
    }

    /// Waits for all issued instructions to retire.
    pub fn wait(&mut self, options: &RunProgramOptions) -> crate::Result<()> {
        self.execute_ready_instructions(true, options)?;

        Ok(())
    }

    /// Does the following:
    /// * Allocate space for the return value (if sized).
    /// * Push all the given args onto the stack.
    /// * Write the address of the return value to A0.
    /// * Align the stack to a 16-byte boundary and write it to SP.
    /// * Returns the return value address.
    ///
    /// # Remarks
    /// Parasol stacks grow down.
    ///
    /// If a return value exists, first push space for it on the stack. Then arguments
    /// are pushed in reverse order so the first argument is closest to the
    /// top of the stack. Padding may be introduces to respect argument's alignment
    /// requirements.
    ///
    /// The final stack location will be 16-byte aligned to allow the callee to correctly
    /// use it without dealing with misaligned accesses.
    ///
    /// If the size of the return value is 0, the return pointer's contents are undefined.
    fn set_up_function_call<T>(&mut self, memory: &Memory, args: &CallData<T>) -> Result<Ptr32> {
        let call_data_size = args.alloc_size();

        memory.try_push_arg_onto_stack(&Arg {
            bytes: vec![Byte::Plaintext(0); call_data_size],
            alignment: 1,
        })?;

        let sp = memory.stack_ptr();
        let mut after_call_data = sp;

        // First write our arguments to our stack allocation
        for arg in args.args.iter() {
            // Align our object
            let align = arg.alignment as u32;
            after_call_data.0 += (align - after_call_data.0 % align) % align;

            for b in arg.bytes.iter() {
                memory.try_store(after_call_data, b.clone())?;
                after_call_data = after_call_data.try_offset(1)?;
            }
        }

        // Allocate space for our return value.
        let return_ptr = if args.return_value.size > 0 {
            let align = args.return_value.alignment as u32;
            after_call_data.0 += (align - after_call_data.0 % align) % align;
            after_call_data
        } else {
            Ptr32(0)
        };

        let rob_a0 = self.registers.rename(RP, None);
        let rob_sp = self.registers.rename(SP, None);

        unwrap_registers!((mut rob_a0));
        unwrap_registers!((mut rob_sp));

        *rob_a0 = Register::Plaintext {
            val: return_ptr.0.into(),
            width: 32,
        };
        *rob_sp = Register::Plaintext {
            val: sp.0.into(),
            width: 32,
        };

        Ok(return_ptr)
    }

    fn reset(&mut self) -> Result<()> {
        // Zero all the registers
        for r in 0..self.registers.rename.len() {
            let rob = self.registers.rename(RegisterName::new(r), None);

            unwrap_registers!((mut rob));

            *rob = Register::Plaintext { val: 0, width: 32 }
        }

        self.debug_handlers = vec![];

        Ok(())
    }

    fn try_capture_return_value<T: ToArg>(
        &self,
        memory: &Arc<Memory>,
        args: &CallData<T>,
        return_value_ptr: Ptr32,
    ) -> Result<T> {
        // If our return value is a ZST, just return a vec of 0 bytes.
        if args.return_value.size == 0 {
            T::try_from_bytes(vec![])
        } else {
            // Read our return value from the return pointer.
            let mut data = Vec::with_capacity(args.return_value.size);

            for i in 0..args.return_value.size {
                data.push(memory.try_load(return_value_ptr.try_offset(i as u32)?)?);
            }

            Ok(T::try_from_bytes(data)?)
        }
    }

    /// Runs the given program using the passed user `data` as arguments with a gas limit
    /// Returns the amount of gas used to run the program and the program return
    /// value
    pub fn run_program_with_options<T: ToArg>(
        &mut self,
        memory: &Arc<Memory>,
        initial_pc: Ptr32,
        args: &CallData<T>,
        options: &RunProgramOptions,
    ) -> Result<(u32, T)> {
        let gas_limit = options.gas_limit();

        self.reset()?;
        let return_data = self.set_up_function_call(memory, args)?;
        self.aux_data.memory = Some(memory.clone());
        self.debug_handlers = options.debug_handlers.clone();

        let mut run_program_impl = || {
            self.pc = initial_pc.0;
            let mut gas = 0;

            loop {
                let inst = memory.try_load_plaintext_dword(self.pc.into())?;
                let inst = IsaOp::try_from(inst)?;

                let pc_result = self.dispatch_instruction(inst, self.pc, options);

                match pc_result {
                    Ok((next_pc, used_gas)) => {
                        gas += used_gas;
                        self.pc = next_pc;
                    }
                    Err(e) => match e {
                        Error::Halt => break,
                        Error::OutOfGas(used_gas, _) => {
                            self.wait(options)?;
                            if let Some(gas_limit) = gas_limit {
                                return Err(Error::OutOfGas(gas + used_gas, gas_limit));
                            } else {
                                // This case should never happen since gas
                                // tracking should throw an out of gas answer
                                // only when the gas_limit is a Some variant.
                                unreachable!()
                            }
                        }
                        _ => return Err(e),
                    },
                }
            }

            self.wait(options)?;

            Ok::<_, Error>(gas)
        };

        let gas = run_program_impl()?;

        // Clear the inflight_memory_ops table so we don't leak memory.
        self.aux_data.inflight_memory_ops.clear();
        self.aux_data.memory = None;

        self.try_capture_return_value(memory, args, return_data)
            .map(|ret_val| (gas, ret_val))
    }

    /// Runs the given program using the passed user `data` as arguments.
    /// Returns the result of the program.
    pub fn run_program<T: ToArg>(
        &mut self,
        memory: &Arc<Memory>,
        initial_pc: Ptr32,
        args: &CallData<T>,
    ) -> Result<T> {
        self.run_program_with_options(
            memory,
            initial_pc,
            args,
            &RunProgramOptionsBuilder::new().build(),
        )
        .map(|x| x.1)
    }
}

impl Tomasulo for FheProcessor {
    type AuxiliaryData = FheProcessorAuxData;
    type DispatchInstruction = DispatchIsaOp;

    fn exec_instruction(
        &mut self,
        scoreboard_entry: ScoreboardEntryRef<Self::DispatchInstruction>,
        retirement_info: RetirementInfo<Self::DispatchInstruction>,
        options: &RunProgramOptions,
    ) {
        // Take the instructon out of the scoreboard entry. We do this because
        // 1. It's not needed after execution.
        // 2. It may contain PtrRegisters, which can create reference cycles
        // with this scoreboard entry. This will leak memory, but removing
        // the instruction will break the cycle.
        let instruction = scoreboard_entry.instruction.borrow_mut().take().unwrap();

        let instruction_id = *scoreboard_entry.id;
        let memory = self.aux_data.memory.as_ref().unwrap().clone();

        let pc = scoreboard_entry.pc;

        use DispatchIsaOp::*;

        if options.log_instruction_execution {
            debug!("executing pc={pc} id={instruction_id} {instruction:#?}");
        }

        match instruction {
            Load(dst, src, width, offset) => {
                self.load(
                    retirement_info,
                    &memory,
                    src,
                    dst,
                    offset,
                    width,
                    instruction_id,
                    pc,
                );
            }
            LoadI(dst, imm, width) => {
                self.loadi(retirement_info, dst, imm, width, instruction_id, pc);
            }
            Store(dst, src, width, offset) => {
                self.store(
                    retirement_info,
                    &memory,
                    src,
                    dst,
                    offset,
                    width,
                    instruction_id,
                    pc,
                );
            }
            Move(dst, src) => {
                self.mov(retirement_info, dst, src);
            }
            And(dst, a, b) => {
                self.and(retirement_info, dst, a, b, instruction_id, pc);
            }
            Or(dst, a, b) => {
                self.or(retirement_info, dst, a, b, instruction_id, pc);
            }
            Not(dst, src) => {
                self.not(retirement_info, dst, src, instruction_id, pc);
            }
            Xor(dst, a, b) => {
                self.xor(retirement_info, dst, a, b, instruction_id, pc);
            }
            Shr(dst, src, shift) => {
                self.shr(retirement_info, dst, src, shift);
            }
            Shra(dst, src, shift) => {
                self.shra(retirement_info, dst, src, shift);
            }
            Shl(dst, src, shift) => {
                self.shl(retirement_info, dst, src, shift);
            }
            Rotr(dst, src, shift) => {
                self.rotr(retirement_info, dst, src, shift);
            }
            Rotl(dst, src, shift) => {
                self.rotl(retirement_info, dst, src, shift);
            }
            Add(dst, a, b) => {
                self.add(retirement_info, dst, a, b, instruction_id, pc);
            }
            AddC(dst, carry_out, a, b, carry_in) => {
                self.add_carry(
                    retirement_info,
                    dst,
                    carry_out,
                    a,
                    b,
                    carry_in,
                    instruction_id,
                    pc,
                );
            }
            Mul(dst, a, b) => {
                self.unsigned_multiply(retirement_info, dst, a, b, instruction_id, pc);
            }
            Sub(dst, a, b) => {
                self.sub(retirement_info, dst, a, b, instruction_id, pc);
            }
            SubB(dst, borrow_out, a, b, borrow_in) => {
                self.sub_borrow(
                    retirement_info,
                    dst,
                    borrow_out,
                    a,
                    b,
                    borrow_in,
                    instruction_id,
                    pc,
                );
            }
            Neg(dst, a) => {
                self.neg(retirement_info, dst, a, instruction_id, pc);
            }
            CmpEq(dst, a, b) => {
                self.equal(retirement_info, dst, a, b, instruction_id, pc);
            }
            CmpGt(dst, a, b) => {
                self.greater_than(retirement_info, dst, a, b, instruction_id, pc);
            }
            CmpGe(dst, a, b) => {
                self.greater_than_or_equal(retirement_info, dst, a, b, instruction_id, pc);
            }
            CmpLt(dst, a, b) => {
                self.less_than(retirement_info, dst, a, b, instruction_id, pc);
            }
            CmpLe(dst, a, b) => {
                self.less_than_or_equal(retirement_info, dst, a, b, instruction_id, pc);
            }
            CmpGtS(dst, a, b) => {
                self.greater_than_signed(retirement_info, dst, a, b, instruction_id, pc);
            }
            CmpGeS(dst, a, b) => {
                self.greater_than_or_equal_signed(retirement_info, dst, a, b, instruction_id, pc);
            }
            CmpLtS(dst, a, b) => {
                self.less_than_signed(retirement_info, dst, a, b, instruction_id, pc);
            }
            CmpLeS(dst, a, b) => {
                self.less_than_or_equal_signed(retirement_info, dst, a, b, instruction_id, pc);
            }
            Sext(dst, src, width) => {
                self.sext(retirement_info, dst, src, width, instruction_id, pc);
            }
            Zext(dst, src, width) => {
                self.zext(retirement_info, dst, src, width, instruction_id, pc);
            }
            Trunc(dst, src, width) => {
                self.trunc(retirement_info, dst, src, width, instruction_id, pc);
            }
            Cmux(dst, cond, a, b) => {
                self.cmux(retirement_info, dst, cond, a, b, instruction_id, pc);
            }
            // Branch we don't actually deal with in exec_instruction
            BranchNonZero(_cond, _target) => {
                // Retire the instruction
                Self::retire(&retirement_info, Ok(()));
            }
            BranchZero(_cond, _target) => {
                // Retire the instruction
                Self::retire(&retirement_info, Ok(()));
            }
            Branch(..) => {
                Self::retire(&retirement_info, Ok(()));
            }
            Ret() => {
                Self::retire(&retirement_info, Ok(()));
            }
            Dbg(src, handler_id) => {
                self.dbg(&retirement_info, src, handler_id, instruction_id, pc);
            }
        }
    }

    fn next_program_counter(
        &mut self,
        dispatched_op: crate::proc::DispatchIsaOp,
        pc: u32,
    ) -> Result<u32> {
        match dispatched_op {
            DispatchIsaOp::BranchNonZero(cond, pc_offset) => {
                unwrap_registers!((cond));
                if let Register::Plaintext { val, width: _ } = cond {
                    if *val != 0 {
                        Ok(pc.wrapping_add_signed(pc_offset))
                    } else {
                        Ok(pc + INSTRUCTION_SIZE)
                    }
                } else {
                    Err(Error::BranchConditionNotPlaintext)
                }
            }
            DispatchIsaOp::BranchZero(cond, pc_offset) => {
                unwrap_registers!((cond));
                if let Register::Plaintext { val, width: _ } = cond {
                    if *val == 0 {
                        Ok(pc.wrapping_add_signed(pc_offset))
                    } else {
                        Ok(pc + INSTRUCTION_SIZE)
                    }
                } else {
                    Err(Error::BranchConditionNotPlaintext)
                }
            }
            DispatchIsaOp::Branch(pc_offset) => Ok(pc.wrapping_add_signed(pc_offset)),
            DispatchIsaOp::Ret() => Err(Error::Halt),
            _ => Ok(pc + INSTRUCTION_SIZE),
        }
    }
}
