use std::ffi::FromBytesUntilNulError;

use elf::ParseError;
use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
/// Errors that can occur in this crate.
pub enum Error {
    /// Illegal operands to an instruction.
    #[error("(inst:{inst_id}, pc:0x{pc:x}) Illegal operands executing instruction at PC")]
    IllegalOperands {
        /// The faulting instruction's id.
        inst_id: usize,

        /// The program counter at time of error.
        pc: usize,
    },

    /// Operands have mismatched bit widths.
    #[error("(inst:{inst_id}, pc:0x{pc:x}): Operation width mismatch")]
    WidthMismatch {
        /// The faulting instruction's id.
        inst_id: usize,

        /// The program counter at time of error.
        pc: usize,
    },

    /// The instruction attempted an unaligned memory operation.
    #[error("(inst:{inst_id}, pc:0x{pc:x}): Unaligned access")]
    UnalignedAccess {
        /// The faulting instruction's id.
        inst_id: usize,

        /// The program counter at time of error.
        pc: usize,
    },

    /// Processor violated a register mutability invariant. This is an internal error and should
    /// be reported as a bug.
    #[error("Internal error: Attempted to mutably access immutable register")]
    RegisterMutabilityViolation,

    /// A bind instruction attempted to bind a buffer of a different encrypted-ness than the bind
    /// instruction specified.
    #[error(
        "(inst_id:{inst_id}, pc:0x{pc:x}) Program input/output expected plaintext/ciphertext buffer, but found the other"
    )]
    BufferMismatch {
        /// The faulting instruction's id.
        inst_id: usize,

        /// The program counter at time of error.
        pc: usize,
    },

    /// The user-passed memory array did not have a buffer corresponding to a bind instructions
    /// buffer index.
    #[error("(inst_id:{inst_id}, pc:0x{pc:x}) No buffer at the given index")]
    NoBuffer {
        /// The faulting instruction's id.
        inst_id: usize,

        /// The program counter at time of error.
        pc: usize,
    },

    /// Encountered multiple bind instructions with the same buffer index.
    #[error(
        "(inst_id:{inst_id}, pc:0x{pc:x}) Buffer {buffer_id} is already declared as an input or output"
    )]
    AliasingViolation {
        /// The faulting instruction's id.
        inst_id: usize,

        /// The program counter at time of error.
        pc: usize,

        /// The buffer's index in a call to [`crate::FheComputer::run_program`].
        buffer_id: usize,
    },

    /// A load or store occured out of a memory's bounds.
    #[error("Attempted to access unmapped address 0x{0:8x}")]
    AccessViolation(u32),

    /// Cannot load or store a value of the requested width (> 128 bits).
    #[error("(inst:{inst_id}, pc:0x{pc:x}) Attempted load or store with zero or > 128 width")]
    UnsupportedWidth {
        /// The faulting instruction's id.
        inst_id: usize,

        /// The program counter at time of error.
        pc: usize,
    },

    /// An instruction's immediate value is too large.
    #[error("(inst:{inst_id}, pc:0x{pc:x}) Immediate value is out of range for the given width")]
    OutOfRange {
        /// The faulting instruction's id.
        inst_id: usize,

        /// The program counter at time of error.
        pc: usize,
    },

    /// The given buffer wasn't a plaintext.
    #[error("The given buffer wasn't a plaintext")]
    BufferNotAPlaintext,

    /// The given buffer wasn't encrypted.
    #[error("The given buffer wasn't a ciphertext")]
    BufferNotACiphertext,

    /// The buffer had the wrong size.
    #[error("The given buffer is the wrong size for the given type")]
    BufferSizeMismatch,

    /// A register was in the wrong ciphertext form when executing an operation. This is an internal
    /// error and should be reported as a bug.
    #[error("Encountered an invalid ciphertext type executing an op")]
    RegisterCiphertextMismatch,

    /// Encountered an illegal micro-op. This is a bug.
    #[error("The processor executed an illegal uop")]
    IllegalUop,

    /// A micro-op encountered an unexpected ciphertext type. This is a bug.
    #[error("Encountered an invalid ciphertext type executing a uop")]
    UopCiphertextMismatch,

    /// Attempted to branch on an encrypted value.
    #[error("Branch condition is not a plaintext value")]
    BranchConditionNotPlaintext,

    /// Internally used to signal a program halting. Should never be encountered.
    #[error("Program halted")]
    Halt,

    /// The given ELF file is not runnable. It has no section headers.
    #[error("ELF file has no section headers")]
    ElfNoSectionHeaders,

    /// Failed to parse the given ELF file.
    #[error("ELF parse error: {0}")]
    ElfParseError(String),

    /// Encountered an illegal string in the given ELF program.
    #[error("Elf malformed string: {0}")]
    ElfMalformedString(#[from] FromBytesUntilNulError),

    /// An unexpected error occurred. This should never happen.
    #[error("The ELF file is malformed in a way that should be impossible")]
    ElfUnreachable,

    /// Attempted to load an elf file with an unsupported ABI version.
    #[error("ELF file has an unsupported ABI version: {0}")]
    ElfUnsupportedAbiVersion(u8),

    /// The ELF file lacks a symbol table, and thus cannot be loaded.
    #[error("ELF file has no symbol table")]
    ElfNoSymbolTable,

    /// The ELF file lacks a segment table, and thus cannot be loaded.
    #[error("ELF file has no segment table")]
    ElfNoSegmentTable,

    /// The given ELF file is ELF64.
    #[error("ELF file is not ELF32")]
    ElfNotElf32,

    /// The specified symbol does not exist the ELF file.
    #[error("The ELF file does not contain the specified symbol: {0}")]
    ElfSymbolNotFound(String),

    /// When parsing the ELF file, encountered an out-of-bounds file offset.
    #[error("The given ELF byte offset {0} exceeds the file's length")]
    ElfByteOutOfBounds(u32),

    /// Attempted to allocate a virtual address that's already mapped.
    #[error("Failed to allocate virtual address space. Already in use")]
    VirtualAddressInUse,

    /// Failed to create a [`std::ffi::CString`]`
    #[error("Failed to create CString: {0}")]
    CStringCreationError(#[from] std::ffi::NulError),

    /// Cannot fulfill the given mmap request as no contiguous address region exists of the
    /// requested length
    #[error("Failed to mmap {0} bytes")]
    NoContiguousChunk(u32),

    /// Attempted to mmap zero bytes.
    #[error("Cannot mmap zero bytes")]
    ZeroAllocation,

    /// Attempted an operation that resulted in pointer overflow.
    #[error("32-bit Pointer overflow")]
    PointerOverflow,
}

// Stupid ParseError isn't Clone, so we gotta stringify it
impl From<ParseError> for Error {
    fn from(value: ParseError) -> Self {
        Self::ElfParseError(format!("{value:#?}"))
    }
}

impl Error {
    /// Create an [`Error::AliasingViolation`].
    pub fn aliasing_violation(inst_id: usize, pc: usize, buffer_id: usize) -> Self {
        Self::AliasingViolation {
            inst_id,
            pc,
            buffer_id,
        }
    }

    /// Create an [`Error::UnsupportedWidth`].
    pub fn unsupported_width(inst_id: usize, pc: usize) -> Self {
        Self::UnsupportedWidth { inst_id, pc }
    }

    /// Create an [`Error::BufferNotAPlaintext`].
    pub fn buffer_not_a_plaintext() -> Self {
        Self::BufferNotAPlaintext
    }

    /// Create an [`Error::BufferNotACiphertext`].
    pub fn buffer_not_a_ciphertext() -> Self {
        Self::BufferNotACiphertext
    }

    /// Create an [`Error::BufferSizeMismatch`].
    pub fn buffer_size_mismatch() -> Self {
        Self::BufferSizeMismatch
    }

    /// Create an [`Error::UopCiphertextMismatch`].
    pub fn uop_ciphertext_mismatch() -> Self {
        Self::UopCiphertextMismatch
    }

    /// Create an [`Error::OutOfRange`].
    pub fn out_of_range(inst_id: usize, pc: usize) -> Self {
        Self::OutOfRange { inst_id, pc }
    }

    /// Create an [`Error::NoBuffer`].
    pub fn no_buffer(inst_id: usize, pc: usize) -> Self {
        Error::NoBuffer { inst_id, pc }
    }
}

/// Results for this crate.
pub type Result<T> = std::result::Result<T, Error>;
