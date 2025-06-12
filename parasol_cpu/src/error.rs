use std::ffi::FromBytesUntilNulError;

use elf::ParseError;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
/// Errors that can occur in this crate.
pub enum Error {
    /// An error occurred when processing a running a circuit on a
    /// [`parasol_runtime::UOpProcessor`].
    #[error("Circuit error: {0}")]
    CircuitError(#[from] parasol_runtime::RuntimeError),

    /// Illegal instruction.
    #[error("Illegal instruction encountered at 0x{0:8x}")]
    IllegalInstruction(u32),

    /// Illegal operands to an instruction.
    #[error("(inst:{inst_id}, pc:0x{pc:x}) Illegal operands executing instruction at PC")]
    IllegalOperands {
        /// The faulting instruction's id.
        inst_id: usize,

        /// The program counter at time of error.
        pc: u32,
    },

    /// Operands have mismatched bit widths.
    #[error("(inst:{inst_id}, pc:0x{pc:x}): Operation width mismatch")]
    WidthMismatch {
        /// The faulting instruction's id.
        inst_id: usize,

        /// The program counter at time of error.
        pc: u32,
    },

    /// The instruction attempted an unaligned memory operation.
    #[error("Unaligned access at 0x{0:8x}")]
    UnalignedAccess(u32),

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
        pc: u32,
    },

    /// The user-passed memory array did not have a buffer corresponding to a bind instructions
    /// buffer index.
    #[error("(inst_id:{inst_id}, pc:0x{pc:x}) No buffer at the given index")]
    NoBuffer {
        /// The faulting instruction's id.
        inst_id: usize,

        /// The program counter at time of error.
        pc: u32,
    },

    /// Encountered multiple bind instructions with the same buffer index.
    #[error(
        "(inst_id:{inst_id}, pc:0x{pc:x}) Buffer {buffer_id} is already declared as an input or output"
    )]
    AliasingViolation {
        /// The faulting instruction's id.
        inst_id: usize,

        /// The program counter at time of error.
        pc: u32,

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
        pc: u32,
    },

    /// An instruction's immediate value is too large.
    #[error("(inst:{inst_id}, pc:0x{pc:x}) Immediate value is out of range for the given width")]
    OutOfRange {
        /// The faulting instruction's id.
        inst_id: usize,

        /// The program counter at time of error.
        pc: u32,
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

    /// Attempted to mix plaintext and ciphertext data in a multi-byte type.
    #[error("The given value has a mix of plaintext and encrypted data")]
    MixedData,

    /// Encountered a different byte encrypted-ness than expected.
    #[error("Encountered a different byte encrypted-ness than expected.")]
    EncryptionMismatch,

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

    /// Encountered an STT_FUNC symbol out of range.
    #[error("Encountered an STT_FUNC symbol out of range.")]
    ElfBadSymbolValue,

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

    /// Running out of allowed fee quota
    #[error("Used gas amount {0} is exceeding quota {1}")]
    OutOfGas(u32, u32),

    /// The given byte should have been a plaintext, but was encrypted
    #[error(
        "Byte at address 0x{0:8x} was encrypted. Expected plaintext (was this a CPU instruction?)."
    )]
    UnexpectedEncryptedByte(u32),

    /// Too many bytes given to `Word::try_from()`.
    #[error("When trying to construct a Word, too many bytes were given.")]
    WordConversionTooManyBytes,

    /// When trying to convert to an encrypted byte, found more or less than 8 bits.
    #[error("Expected 8 encrypted bits.")]
    NotAByte,

    /// Attempted to create a value from an incorrect number of bytes.
    #[error("Attempted to create a value from an incorrect number of bytes.")]
    TypeSizeMismatch,
}

// Stupid ParseError isn't Clone, so we gotta stringify it
impl From<ParseError> for Error {
    fn from(value: ParseError) -> Self {
        Self::ElfParseError(format!("{value:#?}"))
    }
}

impl Error {
    /// Create an [`Error::AliasingViolation`].
    pub fn aliasing_violation(inst_id: usize, pc: u32, buffer_id: usize) -> Self {
        Self::AliasingViolation {
            inst_id,
            pc,
            buffer_id,
        }
    }

    /// Create an [`Error::UnsupportedWidth`].
    pub fn unsupported_width(inst_id: usize, pc: u32) -> Self {
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
    pub fn out_of_range(inst_id: usize, pc: u32) -> Self {
        Self::OutOfRange { inst_id, pc }
    }

    /// Create an [`Error::NoBuffer`].
    pub fn no_buffer(inst_id: usize, pc: u32) -> Self {
        Error::NoBuffer { inst_id, pc }
    }
}

/// Results for this crate.
pub type Result<T> = std::result::Result<T, Error>;
