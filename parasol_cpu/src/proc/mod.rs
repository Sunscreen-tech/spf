use std::{array, collections::HashSet, ops::Deref, sync::Arc};

use concurrency::AtomicRefCell;
use parasol_runtime::{
    fluent::UInt, Encryption, Evaluation, L0LweCiphertext, L1GgswCiphertext, L1GlweCiphertext,
    L1LweCiphertext, SecretKey, TrivialOne, TrivialZero, UOpProcessor,
};
use rayon::ThreadPool;
use serde::{Deserialize, Serialize};
use sunscreen_tfhe::entities::Polynomial;

use crate::{
    impl_tomasulo,
    proc::ops::assign_io,
    tomasulo::{
        scoreboard::ScoreboardEntryRef,
        tomasulo_processor::{RetirementInfo, Tomasulo},
    },
    unwrap_registers,
    util::FheBuffer,
    Error, Result,
};

use self::ops::trivially_encrypt_value_l1glwe;

#[doc(hidden)]
pub mod assembly;
mod ops;

#[cfg(test)]
mod tests;

mod program;
pub use program::*;

pub(crate) use assembly::*;

/// Add a dependency between scoreboard entries.
pub fn add_dependency(
    _child: &ScoreboardEntryRef<DispatchIsaOp>,
    _parent: &ScoreboardEntryRef<DispatchIsaOp>,
) {
}

pub(crate) trait MemHazards {
    fn last_write(&self) -> &Option<ScoreboardEntryRef<DispatchIsaOp>>;

    fn last_write_mut(&mut self) -> &mut Option<ScoreboardEntryRef<DispatchIsaOp>>;

    fn on_read(&self, child: &ScoreboardEntryRef<DispatchIsaOp>) {
        if let Some(parent) = self.last_write() {
            add_dependency(child, parent);
        }
    }

    fn on_write(&mut self, child: &ScoreboardEntryRef<DispatchIsaOp>) {
        if let Some(parent) = self.last_write_mut() {
            add_dependency(child, parent);
        }

        *self.last_write_mut() = Some(child.clone());
    }
}

#[doc(hidden)]
pub struct PlaintextPtr {
    base: Arc<Vec<AtomicRefCell<u8>>>,
    offset: u32,
    last_write: Option<ScoreboardEntryRef<DispatchIsaOp>>,
}

impl MemHazards for PlaintextPtr {
    fn last_write(&self) -> &Option<ScoreboardEntryRef<DispatchIsaOp>> {
        &self.last_write
    }

    fn last_write_mut(&mut self) -> &mut Option<ScoreboardEntryRef<DispatchIsaOp>> {
        &mut self.last_write
    }
}

#[doc(hidden)]
pub struct PlainOffsetCtPtr {
    base: Arc<Vec<AtomicRefCell<L1GlweCiphertext>>>,
    offset: u32,
    last_write: Option<ScoreboardEntryRef<DispatchIsaOp>>,
}

impl MemHazards for PlainOffsetCtPtr {
    fn last_write(&self) -> &Option<ScoreboardEntryRef<DispatchIsaOp>> {
        &self.last_write
    }

    fn last_write_mut(&mut self) -> &mut Option<ScoreboardEntryRef<DispatchIsaOp>> {
        &mut self.last_write
    }
}

#[doc(hidden)]
pub struct EncOffsetCtPtr {
    _base: Vec<Arc<AtomicRefCell<L1GlweCiphertext>>>,
    _offset: Vec<Arc<AtomicRefCell<L1GgswCiphertext>>>,
    last_write: Option<ScoreboardEntryRef<DispatchIsaOp>>,
}

impl MemHazards for EncOffsetCtPtr {
    fn last_write(&self) -> &Option<ScoreboardEntryRef<DispatchIsaOp>> {
        &self.last_write
    }

    fn last_write_mut(&mut self) -> &mut Option<ScoreboardEntryRef<DispatchIsaOp>> {
        &mut self.last_write
    }
}

#[doc(hidden)]
pub enum CiphertextPtr {
    PlainOffset(PlainOffsetCtPtr),

    #[allow(unused)]
    EncOffset(EncOffsetCtPtr),
}

impl std::fmt::Debug for CiphertextPtr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CiphertextPtr {{..}} ")
    }
}

#[doc(hidden)]
pub enum PtrRegister {
    Uninit,
    Plaintext(PlaintextPtr),
    Ciphertext(CiphertextPtr),
}

impl TrivialZero for PtrRegister {
    fn trivial_zero(_enc: &Encryption) -> Self {
        PtrRegister::Uninit
    }
}

impl TrivialOne for PtrRegister {
    fn trivial_one(_enc: &Encryption) -> Self {
        PtrRegister::Uninit
    }
}

#[doc(hidden)]
pub enum Ciphertext {
    #[allow(unused)]
    L0Lwe {
        data: Vec<Arc<AtomicRefCell<L0LweCiphertext>>>,
    },
    #[allow(unused)]
    L1Lwe {
        data: Vec<Arc<AtomicRefCell<L1LweCiphertext>>>,
    },
    L1Glwe {
        data: Vec<Arc<AtomicRefCell<L1GlweCiphertext>>>,
    },
    #[allow(unused)]
    L1Ggsw {
        data: Vec<Arc<AtomicRefCell<L1GgswCiphertext>>>,
    },
}

impl Ciphertext {
    pub fn len(&self) -> usize {
        match self {
            Self::L0Lwe { data } => data.len(),
            Self::L1Lwe { data } => data.len(),
            Self::L1Glwe { data } => data.len(),
            Self::L1Ggsw { data } => data.len(),
        }
    }

    #[allow(unused)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[allow(unused)]
    pub fn unwrap_l1glwe(&self) -> &[Arc<AtomicRefCell<L1GlweCiphertext>>] {
        match self {
            Self::L1Glwe { data } => data,
            _ => panic!("Ciphertext was not L1GlweCiphertext"),
        }
    }

    pub fn try_into_l1glwe(&self) -> Result<&[Arc<AtomicRefCell<L1GlweCiphertext>>]> {
        match self {
            Self::L1Glwe { data } => Ok(data),
            _ => Err(Error::RegisterCiphertextMismatch),
        }
    }
}

#[doc(hidden)]
/// The type of value stored in a register.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegisterValueType {
    Plaintext,
    L0LweCiphertext,
    L1LweCiphertext,
    L1GlweCiphertext,
    L1GgswCiphertext,
}

#[doc(hidden)]
pub enum Register {
    Plaintext { val: u128, width: u32 },

    Ciphertext(Ciphertext),
}

impl Register {
    /// How many bits is the value of the register?
    pub fn width(&self) -> usize {
        match self {
            Self::Plaintext { val: _, width } => *width as usize,
            Self::Ciphertext(x) => x.len(),
        }
    }

    /// Is the register a plaintext register?
    pub fn is_plaintext(&self) -> bool {
        matches!(self, Self::Plaintext { val: _, width: _ })
    }

    /// Is the register a ciphertext register?
    pub fn is_ciphertext(&self) -> bool {
        matches!(self, Self::Ciphertext(_))
    }

    /// What type of value is stored in the register?
    pub fn register_value_type(&self) -> RegisterValueType {
        match self {
            Self::Plaintext { val: _, width: _ } => RegisterValueType::Plaintext,
            Self::Ciphertext(Ciphertext::L0Lwe { data: _ }) => RegisterValueType::L0LweCiphertext,
            Self::Ciphertext(Ciphertext::L1Lwe { data: _ }) => RegisterValueType::L1LweCiphertext,
            Self::Ciphertext(Ciphertext::L1Glwe { data: _ }) => RegisterValueType::L1GlweCiphertext,
            Self::Ciphertext(Ciphertext::L1Ggsw { data: _ }) => RegisterValueType::L1GgswCiphertext,
        }
    }
}

impl TrivialZero for Register {
    fn trivial_zero(_enc: &Encryption) -> Self {
        Register::Plaintext { val: 0, width: 1 }
    }
}

impl TrivialOne for Register {
    fn trivial_one(_enc: &Encryption) -> Self {
        Register::Plaintext { val: 1, width: 1 }
    }
}

/// Checks if the width of two registers is the same.
/// Used inside an instruction implementation.
pub fn check_register_width(
    a: &Register,
    b: &Register,
    instruction_id: usize,
    pc: usize,
) -> Result<()> {
    if a.width() != b.width() {
        return Err(Error::WidthMismatch {
            inst_id: instruction_id,
            pc,
        });
    }

    // TODO, relax the 128-bit limitation.
    if a.width() < 1 || a.width() > 128 {
        return Err(Error::unsupported_width(instruction_id, pc));
    }

    Ok(())
}

/// Convert a plaintext register to a L1 GLWE ciphertext register, or copy
/// the existing ciphertext register if it's already in that form.
///
/// Returns `Err` if the register is not a plaintext or L1 GLWE ciphertext
/// register.
pub fn register_to_l1glwe_by_trivial_lift(
    register: &Register,
    zero: &L1GlweCiphertext,
    one: &L1GlweCiphertext,
) -> Result<Vec<Arc<AtomicRefCell<L1GlweCiphertext>>>> {
    match register {
        Register::Plaintext { val, width } => {
            Ok(trivially_encrypt_value_l1glwe(*val, *width, zero, one))
        }
        Register::Ciphertext(Ciphertext::L1Glwe { data }) => Ok(data.clone()),
        _ => Err(Error::RegisterCiphertextMismatch),
    }
}

impl_tomasulo! {
    FheProcessor, IsaOp, DispatchIsaOp,
    [
        (0, Register, register),
        (1, PtrRegister, ptr_register),
    ]
}

impl Tomasulo for FheProcessor {
    type AuxiliaryData = FheProcessorAuxData;
    type ConstantPool = FheProcessorConstantPool;
    type DispatchInstruction = DispatchIsaOp;

    fn exec_instruction(
        &mut self,
        scoreboard_entry: ScoreboardEntryRef<Self::DispatchInstruction>,
        retirement_info: RetirementInfo<Self::DispatchInstruction>,
    ) {
        // Take the instructon out of the scoreboard entry. We do this because
        // 1. It's not needed after execution.
        // 2. It may contain PtrRegisters, which can create reference cycles
        // with this scoreboard entry. This will leak memory, but removing
        // the instruction will break the cycle.
        let instruction = scoreboard_entry.instruction.borrow_mut().take().unwrap();

        let instruction_id = *scoreboard_entry.id;

        let pc = instruction_id;

        use DispatchIsaOp::*;

        match instruction {
            BindReadOnly(ptr, id, enc) => {
                let res = assign_io(
                    &self.constant_pool,
                    ptr,
                    &self.aux_data.data,
                    enc,
                    &mut self.aux_data.used_buffers,
                    id,
                    instruction_id,
                    pc,
                );

                Self::retire(&retirement_info, res);
            }
            BindReadWrite(ptr, id, enc) => {
                let res = assign_io(
                    &self.constant_pool,
                    ptr,
                    &self.aux_data.data,
                    enc,
                    &mut self.aux_data.used_buffers,
                    id,
                    instruction_id,
                    pc,
                );

                Self::retire(&retirement_info, res);
            }
            Load(dst, src, width) => {
                self.load(
                    retirement_info,
                    scoreboard_entry,
                    src,
                    dst,
                    width,
                    instruction_id,
                    pc,
                );
            }
            LoadI(dst, imm, width) => {
                self.loadi(retirement_info, dst, imm, width, instruction_id, pc);
            }
            Store(dst, src, width) => {
                self.store(
                    retirement_info,
                    scoreboard_entry,
                    src,
                    dst,
                    width,
                    instruction_id,
                    pc,
                );
            }
            And(dst, a, b) => {
                // self.and(retirement_info, dst, a, b, instruction_id, pc);
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
                self.shr(retirement_info, dst, src, shift, instruction_id, pc);
            }
            Shl(dst, src, shift) => {
                self.shl(retirement_info, dst, src, shift, instruction_id, pc);
            }
            Rotr(dst, src, shift) => {
                self.rotr(retirement_info, dst, src, shift, instruction_id, pc);
            }
            Rotl(dst, src, shift) => {
                self.rotl(retirement_info, dst, src, shift, instruction_id, pc);
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
            Cea(dst, base, offset) => {
                self.cea(
                    retirement_info,
                    scoreboard_entry,
                    base,
                    offset,
                    dst,
                    instruction_id,
                    pc,
                );
            }
            Ceai(_dst, _base, _offset) => {
                todo!()
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
            Ret() => {
                Self::retire(&retirement_info, Ok(()));
            }
        }
    }

    fn next_program_counter(
        &mut self,
        dispatched_op: crate::proc::DispatchIsaOp,
        pc: usize,
    ) -> Result<usize> {
        match dispatched_op {
            DispatchIsaOp::BranchNonZero(cond, target) => {
                unwrap_registers!([self.constant_pool](cond));
                if let Register::Plaintext { val, width: _ } = cond {
                    if *val != 0 {
                        Ok(target as usize)
                    } else {
                        Ok(pc + 1)
                    }
                } else {
                    Err(Error::BranchConditionNotPlaintext)
                }
            }
            DispatchIsaOp::BranchZero(cond, target) => {
                unwrap_registers!([self.constant_pool](cond));
                if let Register::Plaintext { val, width: _ } = cond {
                    if *val == 0 {
                        Ok(target as usize)
                    } else {
                        Ok(pc + 1)
                    }
                } else {
                    Err(Error::BranchConditionNotPlaintext)
                }
            }
            DispatchIsaOp::Ret() => Err(Error::Halt),
            _ => Ok(pc + 1),
        }
    }
}

impl FheProcessor {
    /// Clear the inputs and outputs to reuse the processor in another program.
    pub fn reset_io(&mut self, data: &[Buffer]) -> Result<()> {
        self.aux_data.used_buffers.clear();
        data.clone_into(&mut self.aux_data.data);

        Ok(())
    }

    /// Runs the given program using the passed user `data` as arguments.
    pub fn run_program(&mut self, program: &[IsaOp], data: &[Buffer]) -> Result<()> {
        self.reset_io(data)?;

        let mut pc = 0;

        while let Some(inst) = program.get(pc) {
            let pc_result = self.dispatch_instruction(inst.clone(), pc);

            if let Err(Error::Halt) = pc_result {
                break;
            } else if let Ok(next_pc) = pc_result {
                pc = next_pc;
            } else {
                pc_result?;
            }
        }

        self.wait()?;

        Ok(())
    }
}

pub(crate) struct FheProcessorAuxData {
    uop_processor: UOpProcessor,
    flow: std::sync::mpsc::Receiver<()>,
    data: Vec<Buffer>,
    used_buffers: HashSet<usize>,
    l1glwe_zero: L1GlweCiphertext,
    l1glwe_one: L1GlweCiphertext,
    enc: Encryption,
}

impl FheProcessorAuxData {
    pub fn new(enc: &Encryption, eval: &Evaluation, thread_pool: Option<Arc<ThreadPool>>) -> Self {
        let (uop_processor, flow) = UOpProcessor::new(1024, thread_pool, eval, enc);

        let l1glwe_zero = L1GlweCiphertext::trivial_zero(enc);
        let l1glwe_one = L1GlweCiphertext::trivial_one(enc);

        Self {
            uop_processor,
            flow,
            data: vec![],
            used_buffers: HashSet::new(),
            l1glwe_zero,
            l1glwe_one,
            enc: enc.clone(),
        }
    }
}

/// The Parasol processor that can run programs over encrypted and plaintext data.
pub struct FheComputer {
    processor: FheProcessor,
}

#[derive(Clone, Serialize, Deserialize)]
/// A buffer to the [`FheComputer`].
pub enum Buffer {
    /// The buffer contains plaintext data.
    Plaintext(Arc<Vec<AtomicRefCell<u8>>>),

    /// The buffer contains encrypted data.
    Ciphertext(Arc<Vec<AtomicRefCell<L1GlweCiphertext>>>),
}

impl Buffer {
    /// Create a plaintext buffer from `x`.
    pub fn plain_from_value<T: FheBuffer>(x: &T) -> Self {
        Self::Plaintext(Arc::new(
            T::clone_into_plaintext(x)
                .into_iter()
                .map(AtomicRefCell::new)
                .collect(),
        ))
    }

    /// Create an encrypted buffer from the value `x` using secret key `sk`.
    pub fn cipher_from_value<T: FheBuffer>(x: &T, enc: &Encryption, sk: &SecretKey) -> Self {
        let x = T::clone_into_plaintext(x);

        let mut poly = Polynomial::zero(enc.params.l1_poly_degree().0);

        let y = x
            .iter()
            .flat_map(|v| array::from_fn::<u8, 8, _>(|i| (v >> i) & 0x1))
            .map(|x| {
                poly.coeffs_mut()[0] = x as u64;

                AtomicRefCell::new(enc.encrypt_glwe_l1_secret(&poly, sk))
            })
            .collect::<Vec<_>>();

        Self::Ciphertext(Arc::new(y))
    }

    /// Create a buffer of size `n` with all values set to trivial zero.
    pub fn trivial_zero(n: usize, enc: &Encryption) -> Self {
        let zero = L1GlweCiphertext::trivial_zero(enc);

        let y = (0..n)
            .map(|_| AtomicRefCell::new(zero.clone()))
            .collect::<Vec<_>>();

        Self::Ciphertext(Arc::new(y))
    }

    /// Create a write buffer. This is a buffer that is only meant to be written
    /// to, and hence contains blank data.
    ///
    /// This is just a wrapper for a trivial zero encryption, but named to make
    /// it clear why the buffer is being made.
    pub fn initialize_encrypted_write_buffer(n: usize, enc: &Encryption) -> Self {
        Self::trivial_zero(n, enc)
    }

    /// Attempt to turn the plaintext buffer `self` back into a `T`.
    pub fn plain_try_into_value<T: FheBuffer>(&self) -> Result<T> {
        T::try_from_plaintext(&self.try_plaintext()?)
    }

    /// Attempt to decrypt `self` using `sk` and return the decrypted bits.
    pub fn cipher_to_bits(&self, enc: &Encryption, sk: &SecretKey) -> Result<Vec<bool>> {
        let pt = self
            .try_ciphertext()?
            .iter()
            .map(|x| enc.decrypt_glwe_l1(x, sk).coeffs()[0] == 1)
            .collect::<Vec<_>>();

        Ok(pt)
    }

    /// Attempt to decrypt the `self` using `sk` and recombobulate the bits back into a `T`.
    pub fn cipher_try_into_value<T: FheBuffer>(
        &self,
        enc: &Encryption,
        sk: &SecretKey,
    ) -> Result<T> {
        let pt = self
            .cipher_to_bits(enc, sk)?
            .chunks(8)
            .map(|x| {
                x.iter().enumerate().fold(0u8, |s, (i, x)| {
                    let bit = *x as u8;

                    s | (bit << i)
                })
            })
            .collect::<Vec<_>>();

        T::try_from_plaintext(&pt)
    }

    fn try_plaintext(&self) -> Result<Vec<u8>> {
        match self {
            Self::Plaintext(x) => Ok(x.iter().map(|x| *x.borrow()).collect()),
            _ => Err(Error::buffer_not_a_plaintext()),
        }
    }

    fn try_ciphertext(&self) -> Result<Vec<L1GlweCiphertext>> {
        match self {
            Self::Ciphertext(x) => Ok(x.iter().map(|x| x.borrow().to_owned()).collect()),
            _ => Err(Error::buffer_not_a_ciphertext()),
        }
    }
}

impl<const N: usize> From<&UInt<N, L1GlweCiphertext>> for Buffer {
    fn from(x: &UInt<N, L1GlweCiphertext>) -> Self {
        let bits = x.bits.iter().map(|x| x.deref().clone()).collect::<Vec<_>>();
        Self::Ciphertext(Arc::new(bits))
    }
}

impl<const N: usize> From<UInt<N, L1GlweCiphertext>> for Buffer {
    fn from(x: UInt<N, L1GlweCiphertext>) -> Self {
        (&x).into()
    }
}

impl<const N: usize> TryFrom<&Buffer> for UInt<N, L1GlweCiphertext> {
    type Error = Error;

    fn try_from(value: &Buffer) -> Result<Self> {
        let bits = value.try_ciphertext()?;
        Ok(UInt::from_bits(bits))
    }
}

impl<const N: usize> TryFrom<Buffer> for UInt<N, L1GlweCiphertext> {
    type Error = Error;

    fn try_from(value: Buffer) -> Result<Self> {
        (&value).try_into()
    }
}

impl FheComputer {
    /// Create a new [`FheComputer`]. Tasks will run on the global [`rayon::ThreadPool`].
    pub fn new(enc: &Encryption, eval: &Evaluation) -> Self {
        let config = FheProcessorRegisterConfig {
            register_num_registers: 64,
            ptr_register_num_registers: 64,
        };

        let aux_data = FheProcessorAuxData::new(enc, eval, None);

        let processor = FheProcessor::new(enc, &config, aux_data);

        Self { processor }
    }

    /// Create a new [`FheComputer`]. Tasks will run on the given [`rayon::ThreadPool`].
    pub fn new_with_threadpool(
        enc: &Encryption,
        eval: &Evaluation,
        thread_pool: Arc<ThreadPool>,
    ) -> Self {
        let config = FheProcessorRegisterConfig {
            register_num_registers: 64,
            ptr_register_num_registers: 64,
        };

        let aux_data = FheProcessorAuxData::new(enc, eval, Some(thread_pool));

        let processor = FheProcessor::new(enc, &config, aux_data);

        Self { processor }
    }

    /// Run the given FHE program with user specified data.
    pub fn run_program(&mut self, program: &FheProgram, data: &[Buffer]) -> Result<()> {
        self.processor.run_program(&program.instructions, data)
    }

    /// Analyze the program and run it with the provided input buffers. Write
    /// output buffers are generated automatically. This assumes that the
    /// ReadWrite buffers are only used for writing. This variant returns the
    /// information about each output buffer, which includes the size of the
    /// buffer and the buffer type.
    ///
    /// Note: This is specific to the way we have generated programs at the
    /// moment. In the future we should encode metadata about the programs in
    /// the ELF file so that we don't have to determine what are inputs and
    /// outputs from the program itself.
    pub fn run_programs_with_generated_write_buffers_info(
        &mut self,
        program: &FheProgram,
        input_buffers: &[Buffer],
    ) -> Result<Vec<(Buffer, BufferInfo)>> {
        let buffer_info = program
            .get_buffer_info()
            .map_err(|x| Error::ElfParseError(x.to_string()))?;

        let mut data: Vec<Buffer> = Vec::new();
        let mut input_counter = 0;
        for info in buffer_info.iter() {
            match info.buffer_type {
                BufferType::Read => {
                    // For Read buffers, get value from inputs and encrypt as UInt
                    let input_buffer = input_buffers
                        .get(input_counter)
                        .ok_or(Error::ElfParseError("Input buffer not found".to_string()))?;
                    data.push(input_buffer.clone());
                    input_counter += 1;
                }
                BufferType::ReadWrite => {
                    // For ReadWrite buffers, generate a write buffer
                    let write_buffer = if info.is_encrypted {
                        Buffer::initialize_encrypted_write_buffer(
                            info.width as usize,
                            &self.processor.aux_data.enc,
                        )
                    } else {
                        // It is unlikely that a program will have a plaintext
                        // output but this should handle it if so.
                        let zero_as_bytes = vec![0u8; (info.width / 8) as usize];
                        Buffer::plain_from_value(&zero_as_bytes)
                    };
                    data.push(write_buffer);
                }
            }
        }

        self.processor.run_program(&program.instructions, &data)?;

        let mut output_buffers = Vec::new();
        for info in buffer_info.iter() {
            if info.buffer_type == BufferType::ReadWrite {
                let output_buffer = &data[info.buffer_id];
                output_buffers.push((output_buffer.clone(), info.to_owned()));
            }
        }

        Ok(output_buffers)
    }

    /// Analyze the program and run it with the provided input buffers. Write
    /// output buffers are generated automatically. This assumes that the
    /// ReadWrite buffers are only used for writing.
    ///
    /// Note: This is specific to the way we have generated programs at the
    /// moment. In the future we should encode metadata about the programs in
    /// the ELF file so that we don't have to determine what are inputs and
    /// outputs from the program itself.
    pub fn run_programs_with_generated_write_buffers(
        &mut self,
        program: &FheProgram,
        input_buffers: &[Buffer],
    ) -> Result<Vec<Buffer>> {
        let outputs = self
            .run_programs_with_generated_write_buffers_info(program, input_buffers)?
            .into_iter()
            .map(|(x, _)| x)
            .collect::<Vec<_>>();

        Ok(outputs)
    }
}

#[cfg(test)]
mod buffer_uint_tests {
    use crate::test_utils::{get_thread_pool, make_computer_128, read_result_sk};
    use crate::tomasulo::registers::RegisterName;

    use super::*;
    use parasol_runtime::fluent::UInt;
    use parasol_runtime::test_utils::{
        get_encryption_128, get_evaluation_128, get_secret_keys_128,
    };
    use rand::{thread_rng, RngCore};

    #[test]
    fn test_uint_buffer_roundtrip() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();

        let val: u16 = 42;

        // Create a UInt with test value 42
        let original: UInt<16, L1GlweCiphertext> = UInt::encrypt_secret(val as u64, &enc, &sk);

        // Convert UInt to Buffer
        let buffer: Buffer = original.clone().into();

        // Check that the buffer matches the value
        let buffer_decrypted_val = buffer.cipher_try_into_value::<u16>(&enc, &sk).unwrap();
        assert_eq!(val, buffer_decrypted_val);

        // Convert Buffer back to UInt
        let roundtrip: UInt<16, L1GlweCiphertext> = buffer.try_into().unwrap();

        // There is no equality check for L1GlweCiphertext, so we serialize the
        // values to compare them.
        assert_eq!(
            bincode::serialize(&original).unwrap(),
            bincode::serialize(&roundtrip).unwrap()
        );
    }

    #[test]
    fn test_buffer_conversion_error() {
        // Test that trying to convert a plaintext Buffer to UInt fails
        let plaintext_buffer = Buffer::plain_from_value(&42u8);

        let result: Result<UInt<8, L1GlweCiphertext>> = plaintext_buffer.try_into();
        assert!(result.is_err());
        assert!(
            matches!(result, Err(Error::BufferNotACiphertext)),
            "Expected BufferNotACiphertext error"
        );
    }

    #[test]
    fn test_uint_buffer_addition() {
        let (mut proc, enc) = make_computer_128();
        let sk = get_secret_keys_128();

        // Test multiple random pairs
        for _ in 0..2 {
            // Generate random 16-bit values
            let val1 = thread_rng().next_u64() % (1 << 8);
            let val2 = thread_rng().next_u64() % (1 << 8);
            let expected = (val1 + val2) % (1 << 8); // Wrap around at 16 bits

            // Create UInts and convert to Buffers
            let uint1: UInt<8, L1GlweCiphertext> = UInt::encrypt_secret(val1, &enc, &sk);
            let uint2: UInt<8, L1GlweCiphertext> = UInt::encrypt_secret(val2, &enc, &sk);

            let buffer1: Buffer = uint1.into();
            let buffer2: Buffer = uint2.into();
            let output_buffer = Buffer::initialize_encrypted_write_buffer(8, &enc);

            // Create and run program
            let program = FheProgram::from_instructions(vec![
                IsaOp::BindReadOnly(RegisterName::named(0), 0, true),
                IsaOp::BindReadOnly(RegisterName::named(1), 1, true),
                IsaOp::BindReadWrite(RegisterName::named(2), 2, true),
                IsaOp::Load(RegisterName::named(0), RegisterName::named(0), 8),
                IsaOp::Load(RegisterName::named(1), RegisterName::named(1), 8),
                IsaOp::Add(
                    RegisterName::named(2),
                    RegisterName::named(0),
                    RegisterName::named(1),
                ),
                IsaOp::Store(RegisterName::named(2), RegisterName::named(2), 8),
            ]);

            let params = vec![buffer1, buffer2, output_buffer];
            proc.run_program(&program, &params).unwrap();

            // Convert result back to UInt and verify
            let result_buffer = &params[2];
            let result_uint: UInt<8, L1GlweCiphertext> = result_buffer.try_into().unwrap();
            let actual = result_uint.decrypt(&enc, &sk);

            assert_eq!(
                actual, expected,
                "Addition failed for values {} + {} (expected {}, got {})",
                val1, val2, expected, actual
            );
        }
    }

    #[test]
    fn can_run_on_global_or_local_threadpool() {
        fn case(use_global_threadpool: bool) {
            let enc = get_encryption_128();
            let eval = get_evaluation_128();

            let mut cpu = if use_global_threadpool {
                FheComputer::new(&enc, &eval)
            } else {
                FheComputer::new_with_threadpool(&enc, &eval, get_thread_pool())
            };

            let buffers = vec![
                Buffer::cipher_from_value(&32u8, &enc, &get_secret_keys_128()),
                Buffer::cipher_from_value(&42u8, &enc, &get_secret_keys_128()),
                Buffer::cipher_from_value(&0u8, &enc, &get_secret_keys_128()),
            ];

            let add_program = &FheProgram {
                instructions: vec![
                    IsaOp::BindReadOnly(RegisterName::named(0), 0, true),
                    IsaOp::BindReadOnly(RegisterName::named(1), 1, true),
                    IsaOp::BindReadWrite(RegisterName::named(2), 2, true),
                    IsaOp::Load(RegisterName::named(0), RegisterName::named(0), 8),
                    IsaOp::Load(RegisterName::named(1), RegisterName::named(1), 8),
                    IsaOp::Add(
                        RegisterName::named(2),
                        RegisterName::named(0),
                        RegisterName::named(1),
                    ),
                    IsaOp::Store(RegisterName::named(2), RegisterName::named(2), 8),
                ],
            };

            cpu.run_program(add_program, &buffers).unwrap();

            assert_eq!(
                read_result_sk::<u8>(&buffers[2], &enc, &get_secret_keys_128(), true),
                74
            );
        }

        case(false);
        case(true);
    }
}
