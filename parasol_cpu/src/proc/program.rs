use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    ops::Index,
};

use crate::{Error, Result, proc::IsaOp, tomasulo::registers::RegisterName};
use thiserror::Error;

use elf::{ElfBytes, abi::STT_FUNC, endian::LittleEndian};

// ABI version changes:
// 1:
//   - Organized instructions into groupings
//   - Added rotl, rotr, neg, xor, addc, subb
//   - Note that addc and subb are not currently implemented in the backend, but
//     they do have defined opcodes.
pub(crate) const SUPPORTED_ABI_VERSION: u8 = 1;

enum OpCode {
    // Types and loading
    BindReadOnly,
    BindReadWrite,
    Load,
    LoadI,
    Store,
    Zext,
    Trunc,

    // Arithmetic
    Add,
    AddC,
    Sub,
    SubB,
    Mul,

    // Shifts
    Shl,
    Rotl,
    Shr,
    Rotr,

    // Logic
    And,
    Or,
    Xor,
    Not,
    Neg,

    // Comparison
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
    Cmux,

    // Control flow
    Ret,
    Unknown,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
/// The name of an FHE program as it appears in an ELF file.
pub struct Symbol {
    /// ELF symbols aren't required to be UTF-8, so we must use a
    /// CString to represent them.
    name: CString,
}

impl Symbol {
    /// Create a [`Symbol`] from a [`CStr`].
    pub fn new(name: &CStr) -> Self {
        Self {
            name: name.to_owned(),
        }
    }
}

impl From<&CStr> for Symbol {
    fn from(name: &CStr) -> Self {
        Self::new(name)
    }
}

impl From<&str> for Symbol {
    fn from(name: &str) -> Self {
        Self::new(&CString::new(name).unwrap())
    }
}

/// A collection of [`FheProgram`]s parsed out of an ELF file.
pub struct FheApplication {
    programs: HashMap<Symbol, FheProgram>,
}

impl FheApplication {
    /// Retreive an FHE program by its Symbol
    pub fn get_program(&self, name: &Symbol) -> Option<&FheProgram> {
        self.programs.get(name)
    }

    /// Attempt to parse the given bytes as an ELF file and return the resulting [`FheApplication`].
    pub fn parse_elf(binary: &[u8]) -> Result<Self> {
        let elf = ElfBytes::<LittleEndian>::minimal_parse(binary)?;

        let abi_version = elf.ehdr.abiversion;

        if abi_version != SUPPORTED_ABI_VERSION {
            return Err(Error::ElfUnsupportedAbiVersion(abi_version));
        }

        let get_name = |name: u32| -> Result<&CStr> {
            let shstrn = elf
                .section_headers()
                .ok_or(Error::ElfNoSectionHeaders)?
                .get(elf.ehdr.e_shstrndx as usize)?;

            let str_offset = shstrn.sh_offset as usize + name as usize;
            Ok(CStr::from_bytes_until_nul(&binary[str_offset..])?)
        };

        let (sym, _) = elf.symbol_table()?.ok_or(Error::ElfNoSymbolTable)?;

        let mut programs = HashMap::new();

        for s in sym {
            if s.st_symtype() == STT_FUNC {
                let header = elf
                    .section_headers()
                    .ok_or(Error::ElfNoSectionHeaders)?
                    .get(s.st_shndx as usize)?;
                let (data, _) = elf.section_data(&header)?;
                let data = &data[s.st_value as usize..s.st_value as usize + s.st_size as usize];

                let mut code = vec![];

                for inst in data.chunks(8) {
                    // Infallible
                    let inst: [u8; 8] = inst.try_into().unwrap();
                    let inst = u64::from_le_bytes(inst);
                    let inst = Self::parse_instruction(inst);

                    code.push(inst);
                }

                let symbol_name = get_name(s.st_name)?;

                programs.insert(
                    Symbol::new(symbol_name),
                    FheProgram::from_instructions(code),
                );
            }
        }

        Ok(Self { programs })
    }

    fn parse_instruction(encoded: u64) -> IsaOp {
        match Self::get_opcode(encoded) {
            // Types and loading
            OpCode::BindReadOnly => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let buffer_id = Self::get_bind_buffer_id(encoded);
                let is_encrypted = Self::get_bind_is_encrypted(encoded);

                IsaOp::BindReadOnly(dst, buffer_id, is_encrypted)
            }
            OpCode::BindReadWrite => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let buffer_id = Self::get_bind_buffer_id(encoded);
                let is_encrypted = Self::get_bind_is_encrypted(encoded);

                IsaOp::BindReadWrite(dst, buffer_id, is_encrypted)
            }
            OpCode::Load => {
                let register = RegisterName::new(Self::get_dst(encoded));
                let memory_pointer = RegisterName::new(Self::get_src1(encoded));
                let width = Self::get_casting_width(encoded);

                IsaOp::Load(register, memory_pointer, width)
            }
            OpCode::LoadI => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let imm = Self::get_immediate(encoded);
                let width = Self::get_immediate_width(encoded);

                // All immediates are currently 32 bits, so we need to mask off the
                // unused bits. Negative numbers are wrapped.
                let mask = (1u128 << width) - 1;
                let imm = imm & mask;

                IsaOp::LoadI(dst, imm, width)
            }
            OpCode::Store => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src = RegisterName::new(Self::get_src1(encoded));
                let width = Self::get_casting_width(encoded);

                IsaOp::Store(dst, src, width)
            }
            OpCode::Zext => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src = RegisterName::new(Self::get_src1(encoded));
                let width = Self::get_casting_width(encoded);

                IsaOp::Zext(dst, src, width)
            }
            OpCode::Trunc => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src = RegisterName::new(Self::get_src1(encoded));
                let width = Self::get_casting_width(encoded);

                IsaOp::Trunc(dst, src, width)
            }

            // Arithmetic
            OpCode::Add => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src1 = RegisterName::new(Self::get_src1(encoded));
                let src2 = RegisterName::new(Self::get_src2(encoded));

                IsaOp::Add(dst, src1, src2)
            }
            OpCode::AddC => {
                unimplemented!(
                    "Not implemented in the Parasol compiler. This operation should never be generated."
                );
            }
            OpCode::Sub => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src1 = RegisterName::new(Self::get_src1(encoded));
                let src2 = RegisterName::new(Self::get_src2(encoded));

                IsaOp::Sub(dst, src1, src2)
            }
            OpCode::SubB => {
                unimplemented!(
                    "Not implemented in the Parasol compiler. This operation should never be generated."
                );
            }
            OpCode::Mul => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src1 = RegisterName::new(Self::get_src1(encoded));
                let src2 = RegisterName::new(Self::get_src2(encoded));

                IsaOp::Mul(dst, src1, src2)
            }

            // Shifts
            OpCode::Shl => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src1 = RegisterName::new(Self::get_src1(encoded));
                let src2 = RegisterName::new(Self::get_src2(encoded));

                IsaOp::Shl(dst, src1, src2)
            }
            OpCode::Rotl => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src1 = RegisterName::new(Self::get_src1(encoded));
                let src2 = RegisterName::new(Self::get_src2(encoded));

                IsaOp::Rotl(dst, src1, src2)
            }
            OpCode::Shr => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src1 = RegisterName::new(Self::get_src1(encoded));
                let src2 = RegisterName::new(Self::get_src2(encoded));

                IsaOp::Shr(dst, src1, src2)
            }
            OpCode::Rotr => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src1 = RegisterName::new(Self::get_src1(encoded));
                let src2 = RegisterName::new(Self::get_src2(encoded));

                IsaOp::Rotr(dst, src1, src2)
            }

            // Logic
            OpCode::And => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src1 = RegisterName::new(Self::get_src1(encoded));
                let src2 = RegisterName::new(Self::get_src2(encoded));

                IsaOp::And(dst, src1, src2)
            }
            OpCode::Or => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src1 = RegisterName::new(Self::get_src1(encoded));
                let src2 = RegisterName::new(Self::get_src2(encoded));

                IsaOp::Or(dst, src1, src2)
            }
            OpCode::Xor => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src1 = RegisterName::new(Self::get_src1(encoded));
                let src2 = RegisterName::new(Self::get_src2(encoded));

                IsaOp::Xor(dst, src1, src2)
            }
            OpCode::Not => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src = RegisterName::new(Self::get_src1(encoded));

                IsaOp::Not(dst, src)
            }
            OpCode::Neg => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src = RegisterName::new(Self::get_src1(encoded));

                IsaOp::Neg(dst, src)
            }

            // Comparison
            OpCode::Gt => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src1 = RegisterName::new(Self::get_src1(encoded));
                let src2 = RegisterName::new(Self::get_src2(encoded));

                IsaOp::CmpGt(dst, src1, src2)
            }
            OpCode::Ge => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src1 = RegisterName::new(Self::get_src1(encoded));
                let src2 = RegisterName::new(Self::get_src2(encoded));

                IsaOp::CmpGe(dst, src1, src2)
            }
            OpCode::Lt => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src1 = RegisterName::new(Self::get_src1(encoded));
                let src2 = RegisterName::new(Self::get_src2(encoded));

                IsaOp::CmpLt(dst, src1, src2)
            }
            OpCode::Le => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src1 = RegisterName::new(Self::get_src1(encoded));
                let src2 = RegisterName::new(Self::get_src2(encoded));

                IsaOp::CmpLe(dst, src1, src2)
            }
            OpCode::Eq => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let src1 = RegisterName::new(Self::get_src1(encoded));
                let src2 = RegisterName::new(Self::get_src2(encoded));

                IsaOp::CmpEq(dst, src1, src2)
            }
            OpCode::Cmux => {
                let dst = RegisterName::new(Self::get_dst(encoded));
                let select = RegisterName::new(Self::get_src1(encoded));
                let a = RegisterName::new(Self::get_src2(encoded));
                let b = RegisterName::new(Self::get_src3(encoded));

                IsaOp::Cmux(dst, select, a, b)
            }

            // Control flow
            OpCode::Ret => IsaOp::Ret(),
            _ => {
                unimplemented!("Unknown opcode {:x}", encoded & 0xFF);
            }
        }
    }

    fn get_opcode(encoded: u64) -> OpCode {
        match encoded & 0xFF {
            // Types and loading
            0x00 => OpCode::BindReadOnly,
            0x01 => OpCode::BindReadWrite,
            0x02 => OpCode::Load,
            0x03 => OpCode::LoadI,
            0x04 => OpCode::Store,
            0x05 => OpCode::Zext,
            0x06 => OpCode::Trunc,

            // Arithmetic
            0x10 => OpCode::Add,
            0x11 => OpCode::AddC,
            0x12 => OpCode::Sub,
            0x13 => OpCode::SubB,
            0x14 => OpCode::Mul,

            // Shifts
            0x20 => OpCode::Shl,
            0x21 => OpCode::Rotl,
            0x22 => OpCode::Shr,
            0x23 => OpCode::Rotr,

            // Logic
            0x30 => OpCode::And,
            0x31 => OpCode::Or,
            0x32 => OpCode::Xor,
            0x33 => OpCode::Not,
            0x34 => OpCode::Neg,

            // Comparison
            0x40 => OpCode::Gt,
            0x41 => OpCode::Ge,
            0x42 => OpCode::Lt,
            0x43 => OpCode::Le,
            0x44 => OpCode::Eq,
            0x45 => OpCode::Cmux,

            // Control flow
            0xFE => OpCode::Ret,
            _ => OpCode::Unknown,
        }
    }

    fn get_dst(encoded: u64) -> usize {
        ((encoded >> 8) & 0x3F) as usize
    }

    fn get_src1(encoded: u64) -> usize {
        ((encoded >> 14) & 0x3F) as usize
    }

    fn get_src2(encoded: u64) -> usize {
        ((encoded >> 20) & 0x3F) as usize
    }

    fn get_src3(encoded: u64) -> usize {
        ((encoded >> 26) & 0x3F) as usize
    }

    fn get_bind_buffer_id(encoded: u64) -> usize {
        ((encoded >> 14) & 0x3FF) as usize
    }

    fn get_bind_is_encrypted(encoded: u64) -> bool {
        (encoded >> 24) & 0x1 == 1
    }

    fn get_immediate_width(encoded: u64) -> u32 {
        let exponent = ((encoded >> 14) & 0x7) as u32;
        2u32.pow(exponent)
    }

    fn get_immediate(encoded: u64) -> u128 {
        (encoded >> 17) as u128
    }

    fn get_casting_width(encoded: u64) -> u32 {
        let exponent = ((encoded >> 20) & 0x7) as u32;
        2u32.pow(exponent)
    }
}

/// Whether a buffer is bound as read-only or read/write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BufferType {
    /// Buffer is read-only.
    Read,

    /// Buffer is read/write.
    ReadWrite,
}

/// Information about an FHE program's bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferInfo {
    /// The assigned data register for the first load/store on the binding.
    pub register: usize,

    /// Whether the buffer is writable or not.
    pub buffer_type: BufferType,

    /// Whether the buffer is encrypted of not.
    pub is_encrypted: bool,

    /// The buffer's ID.
    pub buffer_id: usize,

    /// The width of the first load/store on the bound buffer.
    pub width: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Information about buffer bindings during a call to [`crate::FheComputer::run_program`].
pub struct ProgramBufferInfo {
    buffers: Vec<BufferInfo>,
}

impl ProgramBufferInfo {
    /// The number of bindings in an [`FheProgram`].
    pub fn len(&self) -> usize {
        self.buffers.len()
    }

    /// Whether the [`FheProgram`] lacks bindings or not.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the number of read-only buffers.
    pub fn num_read_buffers(&self) -> usize {
        self.buffers
            .iter()
            .filter(|info| info.buffer_type == BufferType::Read)
            .count()
    }

    /// Get the number of writable buffers.
    pub fn num_read_write_buffers(&self) -> usize {
        self.buffers
            .iter()
            .filter(|info| info.buffer_type == BufferType::ReadWrite)
            .count()
    }

    /// Return an iterator over the read-only [`BufferInfo`]s.
    pub fn read_buffers(&self) -> impl Iterator<Item = &BufferInfo> {
        self.buffers
            .iter()
            .filter(|info| info.buffer_type == BufferType::Read)
    }

    /// Return an iterator over the read/write [`BufferInfo`]s.
    pub fn read_write_buffers(&self) -> impl Iterator<Item = &BufferInfo> {
        self.buffers
            .iter()
            .filter(|info| info.buffer_type == BufferType::ReadWrite)
    }

    /// Return an iterator over all [`BufferInfo`]s.
    pub fn iter(&self) -> std::slice::Iter<BufferInfo> {
        self.buffers.iter()
    }
}

impl IntoIterator for ProgramBufferInfo {
    type Item = BufferInfo;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.buffers.into_iter()
    }
}

impl Index<usize> for ProgramBufferInfo {
    type Output = BufferInfo;

    fn index(&self, index: usize) -> &Self::Output {
        &self.buffers[index]
    }
}

/// An executable Parasol program located in an ELF file.
pub struct FheProgram {
    pub(crate) instructions: Vec<IsaOp>,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
/// An error when attempting to gather buffer information in an [`FheProgram`]
pub enum BufferInfoError {
    /// Bindings were mismatched.
    #[error("Register bind pointer ID {} and meta ID {} don't match", .0, .1)]
    MismatchedBinding(usize, usize),

    /// Bind instruction's buffer IDs were not sequential.
    #[error("Non-sequential buffer IDs")]
    NonSequentialBufferIds,

    /// Program contained multiple bind instructions binding to the same value.
    #[error("Duplicate binding for register ID {}", .0)]
    DuplicateBinding(usize),
}

impl FheProgram {
    pub(crate) fn from_instructions(inst: Vec<IsaOp>) -> Self {
        Self { instructions: inst }
    }

    /// Get information about a program's bound buffers.
    pub fn get_buffer_info(&self) -> std::result::Result<ProgramBufferInfo, BufferInfoError> {
        let mut bindings = HashMap::new();
        let mut verified_buffers = HashMap::new();

        // Single pass through instructions
        for op in &self.instructions {
            match op {
                IsaOp::BindReadOnly(reg_name, id, encrypted) => {
                    let reg_num = &reg_name.name;

                    if reg_num != id {
                        return Err(BufferInfoError::MismatchedBinding(*reg_num, *id));
                    }
                    if bindings.contains_key(reg_num) {
                        return Err(BufferInfoError::DuplicateBinding(*reg_num));
                    }
                    bindings.insert(*reg_num, (*id, true, *encrypted));
                }
                IsaOp::BindReadWrite(reg_name, id, encrypted) => {
                    let reg_num = &reg_name.name;

                    if reg_num != id {
                        return Err(BufferInfoError::MismatchedBinding(*reg_num, *id));
                    }
                    if bindings.contains_key(reg_num) {
                        return Err(BufferInfoError::DuplicateBinding(*reg_num));
                    }
                    bindings.insert(*reg_num, (*id, false, *encrypted));
                }
                IsaOp::Load(_, reg_name, width) => {
                    let reg_num = &reg_name.name;

                    if let Some(&(id, is_read_only, encrypted)) = bindings.get(reg_num) {
                        if is_read_only {
                            verified_buffers.insert(
                                id,
                                BufferInfo {
                                    register: *reg_num,
                                    buffer_type: BufferType::Read,
                                    is_encrypted: encrypted,
                                    buffer_id: id,
                                    width: *width,
                                },
                            );
                        }
                    }
                }
                IsaOp::Store(reg_name, _, width) => {
                    let reg_num = &reg_name.name;

                    if let Some(&(id, is_read_only, encrypted)) = bindings.get(reg_num) {
                        if !is_read_only {
                            verified_buffers.insert(
                                id,
                                BufferInfo {
                                    register: *reg_num,
                                    buffer_type: BufferType::ReadWrite,
                                    is_encrypted: encrypted,
                                    buffer_id: id,
                                    width: *width,
                                },
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        // Convert to sorted vec and verify sequential IDs
        let mut result: Vec<_> = verified_buffers.into_values().collect();
        result.sort_by_key(|info| info.buffer_id);

        // Verify sequential IDs
        for (i, info) in result.iter().enumerate() {
            if info.buffer_id != i {
                return Err(BufferInfoError::NonSequentialBufferIds);
            }
        }

        Ok(ProgramBufferInfo { buffers: result })
    }
}

impl From<Vec<IsaOp>> for FheProgram {
    fn from(inst: Vec<IsaOp>) -> Self {
        Self { instructions: inst }
    }
}

impl From<&[IsaOp]> for FheProgram {
    fn from(inst: &[IsaOp]) -> Self {
        Self {
            instructions: inst.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    const ELF: &[u8] = include_bytes!("../../tests/test_data/chi_squared.o");

    #[test]
    fn can_parse_elf() {
        let result = FheApplication::parse_elf(ELF).unwrap();

        assert_eq!(result.programs.len(), 1);
        result
            .get_program(&Symbol::new(
                &CString::new("chi_squared_optimized").unwrap(),
            ))
            .unwrap();
    }

    #[test]
    fn test_chi_squared_buffer_info() {
        let result = FheApplication::parse_elf(ELF).unwrap();
        let program = result
            .get_program(&Symbol::from("chi_squared_optimized"))
            .unwrap();
        let buffer_info = program.get_buffer_info().unwrap();

        assert_eq!(buffer_info.len(), 7);

        // Inputs
        assert_eq!(
            buffer_info[0],
            BufferInfo {
                register: 0,
                buffer_type: BufferType::Read,
                is_encrypted: true,
                buffer_id: 0,
                width: 16,
            }
        );

        assert_eq!(
            buffer_info[1],
            BufferInfo {
                register: 1,
                buffer_type: BufferType::Read,
                is_encrypted: true,
                buffer_id: 1,
                width: 16,
            }
        );

        assert_eq!(
            buffer_info[2],
            BufferInfo {
                register: 2,
                buffer_type: BufferType::Read,
                is_encrypted: true,
                buffer_id: 2,
                width: 16,
            }
        );

        // ReadWrites
        assert_eq!(
            buffer_info[3],
            BufferInfo {
                register: 3,
                buffer_type: BufferType::ReadWrite,
                is_encrypted: true,
                buffer_id: 3,
                width: 16,
            }
        );

        assert_eq!(
            buffer_info[4],
            BufferInfo {
                register: 4,
                buffer_type: BufferType::ReadWrite,
                is_encrypted: true,
                buffer_id: 4,
                width: 16,
            }
        );

        assert_eq!(
            buffer_info[5],
            BufferInfo {
                register: 5,
                buffer_type: BufferType::ReadWrite,
                is_encrypted: true,
                buffer_id: 5,
                width: 16,
            }
        );

        assert_eq!(
            buffer_info[6],
            BufferInfo {
                register: 6,
                buffer_type: BufferType::ReadWrite,
                is_encrypted: true,
                buffer_id: 6,
                width: 16,
            }
        );
    }

    #[test]
    fn test_program_buffer_info_methods() {
        let buffers = vec![
            BufferInfo {
                register: 0,
                buffer_type: BufferType::Read,
                is_encrypted: true,
                buffer_id: 0,
                width: 16,
            },
            BufferInfo {
                register: 1,
                buffer_type: BufferType::ReadWrite,
                is_encrypted: true,
                buffer_id: 1,
                width: 16,
            },
            BufferInfo {
                register: 2,
                buffer_type: BufferType::Read,
                is_encrypted: false,
                buffer_id: 2,
                width: 32,
            },
        ];

        let program_info = ProgramBufferInfo { buffers };

        // Test len()
        assert_eq!(program_info.len(), 3);

        // Test num_read_buffers()
        assert_eq!(program_info.num_read_buffers(), 2);

        // Test num_read_write_buffers()
        assert_eq!(program_info.num_read_write_buffers(), 1);

        // Test read_buffers()
        let read_buffers: Vec<_> = program_info.read_buffers().collect();
        assert_eq!(read_buffers.len(), 2);
        assert_eq!(read_buffers[0].register, 0);
        assert_eq!(read_buffers[1].register, 2);

        // Test read_write_buffers()
        let read_write_buffers: Vec<_> = program_info.read_write_buffers().collect();
        assert_eq!(read_write_buffers.len(), 1);
        assert_eq!(read_write_buffers[0].register, 1);

        // Test iter()
        let all_buffers: Vec<_> = program_info.iter().collect();
        assert_eq!(all_buffers.len(), 3);

        // Test Index implementation
        assert_eq!(program_info[0].register, 0);
        assert_eq!(program_info[1].register, 1);
        assert_eq!(program_info[2].register, 2);

        // Test IntoIterator implementation
        let into_iter_buffers: Vec<_> = program_info.into_iter().collect();
        assert_eq!(into_iter_buffers.len(), 3);
        assert_eq!(into_iter_buffers[0].register, 0);
        assert_eq!(into_iter_buffers[1].register, 1);
        assert_eq!(into_iter_buffers[2].register, 2);
    }
}
