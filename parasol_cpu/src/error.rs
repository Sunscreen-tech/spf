use std::ffi::FromBytesUntilNulError;

use elf::ParseError;
use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum Error {
    #[error("(inst:{inst_id}, pc:0x{pc:x}) Illegal operands executing instruction at PC")]
    IllegalOperands { inst_id: usize, pc: usize },

    #[error("(inst:{inst_id}, pc:0x{pc:x}): Operation width mismatch")]
    WidthMismatch { inst_id: usize, pc: usize },

    #[error("(inst:{inst_id}, pc:0x{pc:x}): Unaligned access")]
    UnalignedAccess { inst_id: usize, pc: usize },

    #[error("Internal error: Attempted to mutably access immutable register")]
    RegisterMutabilityViolation,

    #[error(
        "(inst_id:{inst_id}, pc:0x{pc:x}) Program input/output expected plaintext/ciphertext buffer, but found the other"
    )]
    BufferMismatch { inst_id: usize, pc: usize },

    #[error("(inst_id:{inst_id}, pc:0x{pc:x}) No buffer at the given index")]
    NoBuffer { inst_id: usize, pc: usize },

    #[error("(inst_id:{inst_id}, pc:0x{pc:x}) Buffer {buffer_id} is already declared as an input or output.")]
    AliasingViolation {
        inst_id: usize,
        pc: usize,
        buffer_id: usize,
    },

    #[error("Input buffer {buf_id} is is aliased.")]
    InputBindingError { buf_id: usize },

    #[error("An encrypted buffer's length isn't a multiple of 8")]
    InvalidBufferLength,

    #[error("Encrypted input buffer at index {buf_id} has length that isn't a multiple of 8")]
    InvalidInputBufferLength { buf_id: usize },

    #[error("Encrypted output buffer at index {buf_id} has length that isn't a multiple of 8")]
    InvalidOutputBufferLength { buf_id: usize },

    #[error("Output buffer {buf_id} is is aliased.")]
    OutputBindingError { buf_id: usize },

    #[error("(inst:{inst_id}, pc:0x{pc:x}) Attempted to access data out of bounds")]
    AccessViolation { inst_id: usize, pc: usize },

    #[error("(inst:{inst_id}, pc:0x{pc:x}) Attempted load or store with zero or > 128 width.")]
    UnsupportedWidth { inst_id: usize, pc: usize },

    #[error("(inst:{inst_id}, pc:0x{pc:x}) Immediate value is out of range for the given width")]
    OutOfRange { inst_id: usize, pc: usize },

    #[error("The given buffer wasn't a plaintext")]
    BufferNotAPlaintext,

    #[error("The given buffer wasn't a ciphertext")]
    BufferNotACiphertext,

    #[error("The given buffer is the wrong size for the given type")]
    BufferSizeMismatch,

    #[error("Encountered an invalid ciphertext type executing an op")]
    RegisterCiphertextMismatch,

    #[error("The processor executed an illegal uop.")]
    IllegalUop,

    #[error("Encountered an invalid ciphertext type executing a uop")]
    UopCiphertextMismatch,

    #[error("Branch condition is not a plaintext value.")]
    BranchConditionNotPlaintext,

    #[error("Program halted")]
    Halt,

    #[error("ELF file has no section headers")]
    ElfNoSectionHeaders,

    #[error("ELF parse error: {0}")]
    ElfParseError(String),

    #[error("Elf malformed string: {0}")]
    ElfMalformedString(#[from] FromBytesUntilNulError),

    #[error("The ELF file malformed in a way that should be impossible")]
    ElfUnreachable,

    #[error("ELF file has an unsupported ABI version: {0}")]
    ElfUnsupportedAbiVersion(u8),

    #[error("ELF file has no symbol table")]
    NoSymbolTable,

    #[error("ELF file has no segment table")]
    NoSegmentTable,

    #[error("ELF file is not ELF32")]
    NotElf32,

    #[error("The ELF file does not contain the specified symbol: {0}")]
    SymbolNotInElf(String),

    #[error("Failed to allocate virtual address space. Already in use.")]
    VirtualAddressInUse,

    #[error("Failed to create CString: {0}")]
    CStringCreationError(#[from] std::ffi::NulError),
}

// Stupid ParseError isn't Clone, so we gotta stringify it
impl From<ParseError> for Error {
    fn from(value: ParseError) -> Self {
        Self::ElfParseError(format!("{value:#?}"))
    }
}

impl Error {
    pub fn aliasing_violation(inst_id: usize, pc: usize, buffer_id: usize) -> Self {
        Self::AliasingViolation {
            inst_id,
            pc,
            buffer_id,
        }
    }

    pub fn input_binding_error(buf_id: usize) -> Self {
        Self::InputBindingError { buf_id }
    }

    pub fn output_binding_error(buf_id: usize) -> Self {
        Self::OutputBindingError { buf_id }
    }

    pub fn invalid_buffer_length() -> Self {
        Self::InvalidBufferLength
    }

    pub fn invalid_input_buffer_length(buf_id: usize) -> Self {
        Self::InvalidInputBufferLength { buf_id }
    }

    pub fn invalid_output_buffer_length(buf_id: usize) -> Self {
        Self::InvalidOutputBufferLength { buf_id }
    }

    pub fn unsupported_width(inst_id: usize, pc: usize) -> Self {
        Self::UnsupportedWidth { inst_id, pc }
    }

    pub fn buffer_not_a_plaintext() -> Self {
        Self::BufferNotAPlaintext
    }

    pub fn buffer_not_a_ciphertext() -> Self {
        Self::BufferNotACiphertext
    }

    pub fn buffer_size_mismatch() -> Self {
        Self::BufferSizeMismatch
    }

    pub fn uop_ciphertext_mismatch() -> Self {
        Self::UopCiphertextMismatch
    }

    pub fn out_of_range(inst_id: usize, pc: usize) -> Self {
        Self::OutOfRange { inst_id, pc }
    }

    pub fn no_buffer(inst_id: usize, pc: usize) -> Self {
        Error::NoBuffer { inst_id, pc }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
