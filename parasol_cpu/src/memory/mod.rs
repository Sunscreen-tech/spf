// TODO: Remove
#![allow(unused)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{Arg, Error, IsaOp, Result, ToArg};
use elf::{
    ElfBytes,
    abi::{PT_LOAD, STT_FUNC},
    endian::LittleEndian,
    file::Class,
};
use parasol_concurrency::AtomicRefCell;
use parasol_runtime::{Encryption, L1GlweCiphertext};

/// log2(bytes_per_page)
const LOG2_PAGE_SIZE: u32 = 12;

/// The number of bytes in a page.
pub const PAGE_SIZE: u32 = 0x1 << LOG2_PAGE_SIZE;

// The top bits of a pointer indicate the page id.
const PAGE_OFFSET_MASK: u32 = PAGE_SIZE - 1;

// The bottom bits indicate the byte offset.
const PAGE_ID_MASK: u32 = !PAGE_OFFSET_MASK;

// The total number of pages that fit in the 32-bit address space.
const TOTAL_PAGES: u32 = 0x1 << (32 - LOG2_PAGE_SIZE);

// Bytes in a word
pub(crate) const WORD_SIZE: u32 = 4;

// Number of bytes in an instruction
pub(crate) const INSTRUCTION_SIZE: u32 = 8;

// ABI version changes:
// 1:
//   - Organized instructions into groupings
//   - Added rotl, rotr, neg, xor, addc, subb
//   - Note that addc and subb are not currently implemented in the backend, but
//     they do have defined opcodes.
pub(crate) const SUPPORTED_ABI_VERSION: u8 = 1;

/// An encrypted or unencrypted 32-bit value.
///
/// # Remarks
/// All bytes must be plaintext or ciphertext; you cannot mix encrypted-ness.
pub struct Word(pub [Byte; (WORD_SIZE as usize)]);

impl From<u32> for Word {
    fn from(value: u32) -> Self {
        Self(value.to_le_bytes().map(Byte::from))
    }
}

impl From<u16> for Word {
    fn from(value: u16) -> Self {
        Self::from(value as u32)
    }
}

impl From<u8> for Word {
    fn from(value: u8) -> Self {
        Self::from(value as u32)
    }
}

impl TryFrom<&[Byte]> for Word {
    type Error = Error;

    fn try_from(value: &[Byte]) -> std::result::Result<Self, Self::Error> {
        if value.len() > 4 {
            return Err(Error::WordConversionTooManyBytes);
        }

        let mut word = Word(std::array::from_fn(|_| Byte::Plaintext(0)));

        for (o, i) in word.0.iter_mut().zip(value.iter()) {
            *o = i.clone();
        }

        Ok(word)
    }
}

#[derive(Debug, Clone, Copy)]
/// How to extend an N-byte value to M >= N byte value.
pub enum Extend {
    /// Fill any higher-order bytes with zero. Unsigned data should use this.
    Zero,

    /// Fill higher-order bytes with the most significant bit. Signed data should use this.
    Signed,
}

impl Word {
    /// Convert a slice of 0 to 4 bytes into a [`Word`] using the extension technique
    /// dictated by [`Extend`].
    pub fn try_from_bytes(data: &[Byte], extend: Extend, enc: &Encryption) -> Result<Self> {
        if data.len() > 4 {
            return Err(Error::WordConversionTooManyBytes);
        }

        if data.is_empty() {
            return Ok(Word(std::array::from_fn(|_| Byte::from(0u8))));
        }

        match &data[0] {
            Byte::Plaintext(val) => {
                if data.iter().any(|x| matches! {x, Byte::Ciphertext(_)}) {
                    return Err(Error::MixedData);
                }
            }
            Byte::Ciphertext(val) => {
                if data.iter().any(|x| matches! {x, Byte::Plaintext(_)}) {
                    return Err(Error::MixedData);
                }
            }
        }

        // Get the sign extension byte
        let ext = match (data.last().unwrap(), extend) {
            (Byte::Plaintext(_), Extend::Zero) => Byte::from(0u8),
            (Byte::Ciphertext(_), Extend::Zero) => {
                let zero = (0..8)
                    .map(|_| Arc::new(AtomicRefCell::new(enc.trivial_glwe_l1_zero())))
                    .collect::<Vec<_>>();
                Byte::try_from(zero).unwrap()
            }
            (Byte::Plaintext(val), Extend::Signed) => {
                let sext = if val >> 7 == 0x1 { 0xFFu8 } else { 0 };
                Byte::from(sext)
            }
            (Byte::Ciphertext(val), Extend::Signed) => {
                let sext = (0..8)
                    .map(|_| val.last().unwrap().clone())
                    .collect::<Vec<_>>();
                Byte::try_from(sext).unwrap()
            }
        };

        let mut ret = Word::from(0u32);

        for (i, o) in data.iter().zip(ret.0.iter_mut()) {
            o.clone_from(i);
        }

        for i in data.len()..4 {
            ret.0[i].clone_from(&ext);
        }

        Ok(ret)
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Hash)]
/// A 32-bit pointer.
pub struct Ptr32(pub(crate) u32);

impl From<u32> for Ptr32 {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Ptr32> for u32 {
    fn from(val: Ptr32) -> Self {
        val.0
    }
}

impl ToArg for Ptr32 {
    const ALIGNMENT: usize = u32::ALIGNMENT;
    const SIZE: usize = u32::SIZE;
    const SIGNED: bool = false;

    fn to_bytes(&self) -> Vec<Byte> {
        self.0.to_bytes()
    }

    fn try_from_bytes(data: Vec<Byte>) -> Result<Self> {
        Ok(Self(u32::try_from_bytes(data)?))
    }
}

impl Ptr32 {
    /// Offsets this pointer by `val` and returns a pointer to the new location.
    ///
    /// # Remarks
    /// Returns an error if the pointer arithmetic unsigned overflows.
    pub fn try_offset(&self, val: u32) -> Result<Self> {
        Ok(self
            .0
            .checked_add(val)
            .ok_or(Error::PointerOverflow)?
            .into())
    }

    /// Offsets this pointer by signed `val` and returns a pointer to the new location.
    ///
    /// # Remarks
    /// Returns an error if the pointer arithmetic unsigned overflows.
    pub fn try_signed_offset(&self, val: i32) -> Result<Self> {
        Ok(self
            .0
            .checked_add_signed(val)
            .ok_or(Error::PointerOverflow)?
            .into())
    }
}

/// The memory used by a [`crate::FheComputer`] during computation. The Parasol processor uses
/// a Von Neumann architecture, meaning
///
/// # Remarks
/// Internally, uses virtual memory techniques to provide a 32-bit address space.
pub struct Memory {
    pages: Mutex<Vec<Option<Page>>>,
    stack_ptr: Mutex<Ptr32>,
    symbols: HashMap<String, Ptr32>,
}

impl Memory {
    /// Instantiate a [`Memory`] object and initialize it with the memory segments in the contained
    /// ELF file's bytes.
    ///
    /// # Remarks
    /// `elf_data` should contain the contents of an executable ELF file generated by the Parasol
    /// linker.
    pub fn new_from_elf(elf_data: &[u8]) -> Result<Self> {
        let mut memory = Self::new(Ptr32(0xFFFF_FFFF - 16384), 16384);

        let elf = ElfBytes::<LittleEndian>::minimal_parse(elf_data)?;

        let abi_version = elf.ehdr.abiversion;

        if elf.ehdr.class != Class::ELF32 {
            return Err(Error::ElfNotElf32);
        }

        let segments = elf.segments().ok_or(Error::ElfNoSegmentTable)?;

        // Load all the PT_LOAD segments
        for segment in segments {
            // Skip non-loadable or zero-length segments.
            if segment.p_type != PT_LOAD || segment.p_memsz == 0 {
                continue;
            }

            if segment.p_memsz > u32::MAX as u64
                || segment.p_vaddr > u32::MAX as u64
                || segment.p_offset > u32::MAX as u64
                || segment.p_filesz > u32::MAX as u64
            {
                // Should be unreachable if elf crate is correct.
                return Err(Error::ElfUnreachable);
            }

            let mem_start = Ptr32::from(segment.p_vaddr as u32);
            let mem_end = mem_start.try_offset(segment.p_memsz as u32)?;

            // Not actually a pointer, but ELF32 specifies 32-bit offsets for files.
            let file_start = Ptr32::from(segment.p_offset as u32);
            let file_end = file_start.try_offset(segment.p_filesz as u32)?;

            // The ELF specification allows p_memsz > p_filesz, which should be filled with zeros.
            // However, page allocation zeros the full region, so this case is already handled
            // for us.
            memory.try_allocate_at(mem_start, segment.p_memsz as u32)?;

            // Copy the bytes from the ELF file into memory
            for (i, (f, m)) in (file_start.0..file_end.0)
                .zip(mem_start.0..mem_end.0)
                .enumerate()
            {
                let byte = elf_data
                    .get(f as usize)
                    .ok_or(Error::ElfByteOutOfBounds(f))?;

                memory.try_store(m.into(), Byte::Plaintext(*byte))?;
            }
        }

        let (syms, sym_names) = elf.symbol_table()?.ok_or(Error::ElfNoSymbolTable)?;

        // Create our symbol table.
        for sym in syms {
            if sym.st_symtype() != STT_FUNC {
                continue;
            }

            if sym.st_value > u32::MAX as u64 {
                return Err(Error::ElfBadSymbolValue);
            }

            let name = sym_names.get(sym.st_name as usize)?;

            memory
                .symbols
                .insert(name.to_owned(), Ptr32(sym.st_value as u32));
        }

        Ok(memory)
    }

    pub(crate) fn new(stack_start: Ptr32, stack_size: u32) -> Self {
        // Stacks grow downward, so initialize the pointer to the end of the stack rather than
        // the start.
        let memory = Self {
            pages: Mutex::new(vec![None; TOTAL_PAGES as usize]),
            stack_ptr: Mutex::new(stack_start.try_offset(stack_size).unwrap()),
            symbols: HashMap::new(),
        };

        memory.try_allocate_at(stack_start, stack_size).unwrap();

        memory
    }

    pub(crate) fn new_default_stack() -> Self {
        Memory::new(Ptr32::from(0x8000_0000), 4096)
    }

    pub(crate) fn allocate_program(&self, program: &[IsaOp]) -> Ptr32 {
        let byte_len = (program.len() * std::mem::size_of::<u64>()) as u32;
        let addr = self.try_allocate(byte_len).unwrap();

        for (i, inst) in program.iter().copied().map(u64::from).enumerate() {
            for (j, b) in inst.to_le_bytes().iter().enumerate() {
                let offset = (std::mem::size_of::<u64>() * i + j) as u32;
                self.try_store(addr.try_offset(offset).unwrap(), Byte::from(*b));
            }
        }

        addr
    }

    /// Lookup a function of the given name and return its address
    /// (if it exists).
    pub fn get_function_entry(&self, name: &str) -> Option<Ptr32> {
        self.symbols.get(name).copied()
    }

    /// Attempts to push an item on the stack.
    ///
    /// # Remarks
    /// Will fail if the stack pointer is null or the desired page isn't mapped.
    ///
    /// Parasol stacks grow down.
    pub fn try_push_arg_onto_stack(&self, data: &Arg) -> Result<Ptr32> {
        let mut stack_ptr = self.stack_ptr.lock().unwrap();

        if stack_ptr.0 == 0 {
            return Err(Error::AccessViolation(0));
        }

        let alignment = data.alignment as u32;

        let padding_bytes = (alignment - stack_ptr.0 % alignment) % alignment;

        // Push padding to align data
        for i in 0..padding_bytes {
            self.try_store(*stack_ptr, Byte::from(0))?;
            *stack_ptr = stack_ptr.try_signed_offset(-1)?;
        }

        *stack_ptr = stack_ptr.try_signed_offset(-(data.bytes.len() as i32))?;

        // Write the bytes in the argument
        for (i, b) in data.bytes.iter().enumerate() {
            self.try_store(stack_ptr.try_offset(i as u32)?, b.clone())?;
        }

        Ok(*stack_ptr)
    }

    /// Get the current stack pointer
    pub fn stack_ptr(&self) -> Ptr32 {
        *self.stack_ptr.lock().unwrap()
    }

    /// Allocates `len / PAGE_SIZE` pages starting at `virtual_address`.
    ///
    /// # Remarks
    /// If any pages in the given range are already allocated, they'll simply be retained.
    /// The caller should ensure this won't overwrite existing data.
    fn try_allocate_at(&self, virtual_address: Ptr32, len: u32) -> Result<()> {
        if len == 0 {
            return Err(Error::ZeroAllocation);
        }

        let start_page_id = Page::page_id_from_pointer(virtual_address) as usize;
        let end_page_id = Page::page_id_from_pointer(virtual_address.try_offset(len)?) as usize;

        let mut pages = self.pages.lock().unwrap();

        for i in start_page_id..=end_page_id {
            let _ = pages[i].get_or_insert(Page::allocate());
        }

        Ok(())
    }

    pub(crate) fn try_load(&self, virtual_address: Ptr32) -> Result<Byte> {
        let page_id = Page::page_id_from_pointer(virtual_address) as usize;

        let pages = self.pages.lock().unwrap();

        match &pages[page_id] {
            Some(p) => {
                let page_offset = Page::offset_from_pointer(virtual_address);

                Ok(p.load_byte(page_offset as usize).clone())
            }
            None => Err(Error::AccessViolation(virtual_address.0)),
        }
    }

    pub(crate) fn try_store(&self, virtual_address: Ptr32, data: Byte) -> Result<()> {
        let page_id = Page::page_id_from_pointer(virtual_address) as usize;

        let mut pages = self.pages.lock().unwrap();

        match &mut pages[page_id] {
            Some(p) => {
                let page_offset = Page::offset_from_pointer(virtual_address);
                p.store_byte(page_offset as usize, data);

                Ok(())
            }
            None => Err(Error::AccessViolation(virtual_address.0)),
        }
    }

    pub(crate) fn try_load_plaintext_byte(&self, virtual_address: Ptr32) -> Result<u8> {
        let b = self.try_load(virtual_address)?;

        match b {
            Byte::Plaintext(v) => Ok(v),
            _ => Err(Error::UnexpectedEncryptedByte(virtual_address.0)),
        }
    }

    fn try_load_n_bytes<const N: usize>(&self, virtual_address: Ptr32) -> Result<[u8; N]> {
        let bytes = (0..N)
            .map(|i| {
                virtual_address
                    .try_offset(i as u32)
                    .and_then(|addr| self.try_load_plaintext_byte(addr))
            })
            .collect::<Result<Vec<u8>>>()?
            // Safe to unwrap because we are iterating over a fixed-size array
            .try_into()
            .unwrap();

        Ok(bytes)
    }

    /// Attempt to load a plaintext word from the given address.
    pub(crate) fn try_load_plaintext_word(&self, virtual_address: Ptr32) -> Result<u32> {
        if virtual_address.0 % WORD_SIZE != 0 {
            return Err(Error::UnalignedAccess(virtual_address.0));
        }

        let bytes = self.try_load_n_bytes::<{ WORD_SIZE as usize }>(virtual_address)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Attempt to load a plaintext double word from the given address.
    pub(crate) fn try_load_plaintext_dword(&self, virtual_address: Ptr32) -> Result<u64> {
        if virtual_address.0 % (2 * WORD_SIZE) != 0 {
            return Err(Error::UnalignedAccess(virtual_address.0));
        }

        let bytes = self.try_load_n_bytes::<{ 2 * WORD_SIZE as usize }>(virtual_address)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Allocate a contiguous virtual address region of at least `len` bytes. This also
    /// allocates the backing pages.
    pub fn try_allocate(&self, len: u32) -> Result<Ptr32> {
        if len == 0 {
            return Err(Error::ZeroAllocation);
        }

        let mut pages = self.pages.lock().unwrap();
        let num_pages = len.next_multiple_of(PAGE_SIZE) / PAGE_SIZE;

        // Never allocate the zero page for end-user use. We don't want to ever
        // give a valid null virtual address to user applications, as many languages generate
        // code that assumes you never dereference null pointers.
        let mut base_id = 1;

        // TODO: Do we introduce some partitioning structure to avoid a linear scan through
        // the address space?
        //
        // See https://www.sobyte.net/post/2022-03/mmap/ for more some ideas on how to do this.
        while base_id + num_pages < TOTAL_PAGES {
            if let Some(i) = (base_id..base_id + num_pages).find(|i| pages[*i as usize].is_some()) {
                base_id = i + 1;
                continue;
            }

            for i in base_id..base_id + num_pages {
                pages[i as usize] = Some(Page::allocate());
            }

            return Ok(Ptr32::from(base_id << LOG2_PAGE_SIZE));
        }

        Err(Error::NoContiguousChunk(len))
    }

    /// Attempt to write `x` to the pre-allocated address given by `ptr`.
    ///
    /// # Remarks
    /// `ptr..ptr + T::SIZE` must be in bounds or an error results.
    /// `ptr` must be aligned to T::ALIGNMENT.
    ///
    /// In the event of an error, the contents between addresses `ptr`` and `ptr + T::Size`
    /// are undefined.
    pub fn try_write_type<T: ToArg>(&self, ptr: Ptr32, x: &T) -> Result<()> {
        if ptr.0 % T::ALIGNMENT as u32 != 0 {
            return Err(Error::UnalignedAccess(ptr.0));
        }

        self.check_range_is_mapped(ptr, T::SIZE as u32)?;

        for (i, b) in x.to_bytes().into_iter().enumerate() {
            self.try_store(ptr.try_offset(i as u32)?, b)?;
        }

        Ok(())
    }

    /// Attempt to read a type `T` starting at address ptr.
    pub fn try_load_type<T: ToArg>(&self, ptr: Ptr32) -> Result<T> {
        if ptr.0 % T::ALIGNMENT as u32 != 0 {
            return Err(Error::UnalignedAccess(ptr.0));
        }

        self.check_range_is_mapped(ptr, T::SIZE as u32)?;

        let mut data = Vec::with_capacity(T::SIZE);

        for i in (0..T::SIZE) {
            let b = self.try_load(ptr.try_offset(i as u32)?)?;
            data.push(b);
        }

        T::try_from_bytes(data)
    }

    /// Checks that the given range `ptr..ptr + len` is in bounds.
    ///
    /// # Remarks
    /// Returns an error if pointer arithmetic wraps for an address in the given range
    /// has no page mapping.
    pub fn check_range_is_mapped(&self, ptr: Ptr32, len: u32) -> Result<()> {
        let start_page = ptr.0 / PAGE_SIZE;
        let end_page = (ptr.0 + len) / PAGE_SIZE;

        let pages = self.pages.lock().unwrap();

        for i in start_page..=end_page {
            if pages[i as usize].is_none() {
                return Err(Error::AccessViolation(ptr.try_offset(i * PAGE_SIZE)?.0));
            }
        }

        Ok(())
    }

    /// Attempt to allocate and store `x` in this memory.
    ///
    /// # Remarks
    /// Returns an error if allocation fails or the pointer the allocated
    /// `x` on success.
    pub fn try_allocate_type<T: ToArg>(&self, x: &T) -> Result<Ptr32> {
        let ptr = self.try_allocate(T::SIZE as u32)?;

        self.try_write_type(ptr, x)?;

        Ok(ptr)
    }
}

/// An 8-bit encrypted or plaintext value.
#[derive(Clone)]
pub enum Byte {
    /// A plaintext 8-bit value.
    Plaintext(u8),

    /// An encrypted 8-bit value.
    Ciphertext(Vec<Arc<AtomicRefCell<L1GlweCiphertext>>>),
}

impl From<u8> for Byte {
    fn from(value: u8) -> Self {
        Self::Plaintext(value)
    }
}

impl TryFrom<Vec<Arc<AtomicRefCell<L1GlweCiphertext>>>> for Byte {
    type Error = Error;

    fn try_from(value: Vec<Arc<AtomicRefCell<L1GlweCiphertext>>>) -> Result<Self> {
        if value.len() != 8 {
            return Err(Error::NotAByte);
        }

        Ok(Self::Ciphertext(value))
    }
}

impl Byte {
    /// Whether or not this byte contains plaintext data.
    pub fn is_plaintext(&self) -> bool {
        matches!(self, Self::Plaintext(_))
    }

    /// Whether or not this byte is encrypted.
    pub fn is_ciphertext(&self) -> bool {
        matches!(self, Self::Ciphertext(_))
    }

    /// Unwrap the inner plaintext data or panic if it's a ciphertext.
    ///
    /// # Panics
    /// If the byte contains encrypted data.
    pub fn unwrap_plaintext(self) -> u8 {
        match self {
            Self::Plaintext(val) => val,
            _ => panic!("Not a plaintext"),
        }
    }

    /// Unwrap the inner ciphertext data or panic if it's a plaintext.
    ///
    /// # Panics
    /// If the byte contains plaintext data.
    pub fn unwrap_ciphertext(self) -> Vec<Arc<AtomicRefCell<L1GlweCiphertext>>> {
        match self {
            Self::Ciphertext(val) => val,
            _ => panic!("Not a plaintext"),
        }
    }
}

/// A structure for efficiently placing multiple allocations into a single page
/// allocation request.
pub struct Allocation {
    size: u32,
    next_free: u32,
    base: Ptr32,
}

impl Allocation {
    fn new(memory: &Memory, len: u32) -> Result<(Self, Ptr32)> {
        let base = memory.try_allocate(len)?;

        let allocation = Self {
            size: len.next_multiple_of(PAGE_SIZE),
            next_free: len,
            base,
        };

        Ok((allocation, base))
    }

    /// Allocate `len` bytes of memory, returning the the allocation object
    /// and the pointer to the allocated memory.
    ///
    /// This API allows coalescing multiple allocations into a single virtual
    /// memory allocation, given enough space. For example, if you want to
    /// allocate 32 bytes, the virtual alloc will return `PAGE_SIZE=4096` bytes,
    /// the vast majority of which would otherwise be wasted.
    ///
    /// The first argument is an allocation already returned by this function
    /// (or [`None`] if this is the first allocation request).
    ///
    /// # Remarks
    /// If no `existing` is [`None`], this method will perform a virtual memory
    /// allocation of at least `len` bytes.
    ///
    /// The maximum alignment is [`PAGE_SIZE`] bytes.
    ///
    /// When passing an existing [`Allocation`], this method will attempt to
    /// use the existing virtual memory, assuming it has enough space.
    ///
    /// The returned address with be padded and aligned to `alignment`.
    pub fn try_allocate(
        existing: Option<Self>,
        memory: &Memory,
        len: u32,
        alignment: u32,
    ) -> Result<(Allocation, Ptr32)> {
        let mut existing = match existing {
            Some(e) => e,
            None => {
                return Self::new(memory, len);
            }
        };

        let padded = existing.next_free.next_multiple_of(alignment);

        // If we lack space in this allocation, make another.
        if padded + len >= existing.size {
            return Self::new(memory, len);
        }

        let ptr = existing.base.try_offset(padded)?;

        existing.next_free = ptr.0 + len;

        Ok((existing, ptr))
    }
}

#[derive(Clone)]
struct Page {
    data: Vec<Byte>,
}

impl Page {
    pub fn allocate() -> Self {
        Self {
            data: vec![Byte::Plaintext(0); PAGE_SIZE as usize],
        }
    }

    pub fn load_byte(&self, offset: usize) -> &Byte {
        &self.data[offset]
    }

    pub fn store_byte(&mut self, offset: usize, data: Byte) {
        self.data[offset] = data;
    }

    pub fn page_id_from_pointer(ptr: Ptr32) -> u32 {
        (ptr.0 & PAGE_ID_MASK) >> LOG2_PAGE_SIZE
    }

    pub fn offset_from_pointer(ptr: Ptr32) -> u32 {
        ptr.0 & PAGE_OFFSET_MASK
    }
}

#[cfg(test)]
mod tests {
    use parasol_runtime::{
        DEFAULT_128, Encryption, Evaluation,
        fluent::UInt,
        test_utils::{get_encryption_128, get_evaluation_128, get_secret_keys_128},
    };

    use super::*;

    const CARDIO_O: &[u8] = include_bytes!("test_data/cardio.so");

    fn validate_loader(memory: &Memory, elf: &[u8]) {
        let elf = ElfBytes::<LittleEndian>::minimal_parse(CARDIO_O).unwrap();

        for s in elf.segments().unwrap() {
            let memory_start = s.p_vaddr as u32;
            let memory_end = memory_start + s.p_memsz as u32;
            let file_start = s.p_offset as u32;
            let file_end = file_start + s.p_memsz as u32;

            for (i, (ptr, fileloc)) in (memory_start..memory_end)
                .zip(file_start..file_end)
                .enumerate()
            {
                if i < s.p_filesz as usize {
                    match memory.try_load(ptr.into()).unwrap() {
                        Byte::Plaintext(val) => {
                            assert_eq!(val, CARDIO_O[fileloc as usize]);
                        }
                        Byte::Ciphertext(_) => {
                            panic!("Expected plaintext");
                        }
                    }
                } else {
                    assert!(matches!(
                        memory.try_load(ptr.into()).unwrap(),
                        Byte::Plaintext(0)
                    ));
                }
            }
        }
    }

    #[test]
    fn can_create_memory() {
        let memory = Memory::new_from_elf(CARDIO_O).unwrap();

        validate_loader(&memory, CARDIO_O);
    }

    #[test]
    fn can_allocate_and_write_memory() {
        // Load an ELF file's segments into memory and then allocate additional user buffers
        // into the address space. Verify our ELF segments aren't overwritten and the user's
        // data persists.
        let memory = Memory::new_from_elf(CARDIO_O).unwrap();
        let ptr_plain = memory.try_allocate(32).unwrap();
        let ptr_ct = memory.try_allocate(32).unwrap();

        let enc = get_encryption_128();
        let eval = get_evaluation_128();

        for b in 0..32 {
            memory
                .try_store(ptr_plain.try_offset(b).unwrap(), Byte::Plaintext(b as u8))
                .unwrap();

            let byte_ct =
                Byte::Ciphertext(UInt::<8, L1GlweCiphertext>::trivial(b as u64, &enc, &eval).bits);

            memory.try_store(ptr_ct.try_offset(b).unwrap(), byte_ct);
        }

        // Check that our allocation didn't write somewhere in an ELF segment
        validate_loader(&memory, CARDIO_O);

        for b in 0..32 {
            match memory.try_load(ptr_plain.try_offset(b).unwrap()).unwrap() {
                Byte::Plaintext(v) => assert_eq!(v, b as u8),
                Byte::Ciphertext(_) => panic!("Expected plaintext"),
            }

            match memory.try_load(ptr_ct.try_offset(b).unwrap()).unwrap() {
                Byte::Plaintext(v) => panic!("Expected ciphertext"),
                Byte::Ciphertext(v) => {
                    let val = UInt::<8, _>::from_bits_shallow(v);

                    assert_eq!(val.decrypt(&enc, &get_secret_keys_128()), b as u64);
                }
            }
        }
    }

    #[test]
    fn page_offset() {
        let addr = 0x12345678;

        let offset = Page::offset_from_pointer(addr.into());

        let mask = PAGE_SIZE - 1;

        assert_eq!(offset, addr & mask);
    }

    #[test]
    fn page_id() {
        let addr = 0x12345678;
        let mask = !(PAGE_SIZE - 1);

        let id = Page::page_id_from_pointer(addr.into());

        assert_eq!(id, (addr & mask) >> LOG2_PAGE_SIZE);
    }

    #[test]
    fn word_conversion_plaintext_unsigned() {
        let enc = get_encryption_128();

        let case = |bytes: &[Byte]| {
            let actual = Word::try_from_bytes(bytes, Extend::Zero, &enc).unwrap();

            for (e, a) in bytes.iter().zip(actual.0.iter()) {
                assert_eq!(e.clone().unwrap_plaintext(), a.clone().unwrap_plaintext());
            }

            for a in actual.0.iter().skip(bytes.len()) {
                assert_eq!(0x0, a.clone().unwrap_plaintext());
            }
        };

        case(&[]);
        case(&[Byte::from(0x8D)]);
        case(&[Byte::from(0x8D), Byte::from(0x8D)]);
        case(&[Byte::from(0x8D), Byte::from(0x8D), Byte::from(0x8D)]);
        case(&[
            Byte::from(0x8D),
            Byte::from(0x8D),
            Byte::from(0x8D),
            Byte::from(0x8D),
        ]);
    }

    #[test]
    fn word_conversion_plaintext_signed() {
        let enc = get_encryption_128();

        let case = |bytes: &[Byte], expected_ext: u8| {
            let actual = Word::try_from_bytes(bytes, Extend::Signed, &enc).unwrap();

            for (e, a) in bytes.iter().zip(actual.0.iter()).take(4) {
                assert_eq!(e.clone().unwrap_plaintext(), a.clone().unwrap_plaintext());
            }

            for a in actual.0.iter().skip(bytes.len()) {
                assert_eq!(expected_ext, a.clone().unwrap_plaintext());
            }
        };

        case(&[Byte::from(0x7D)], 0);
        case(&[Byte::from(0x7D), Byte::from(0x7D)], 0);
        case(&[Byte::from(0x7D), Byte::from(0x7D), Byte::from(0x7D)], 0);
        case(
            &[
                Byte::from(0x7D),
                Byte::from(0x7D),
                Byte::from(0x7D),
                Byte::from(0x7D),
            ],
            0,
        );

        case(&[], 0);
        case(&[Byte::from(0x8D)], 0xFF);
        case(&[Byte::from(0x8D), Byte::from(0x8D)], 0xFF);
        case(
            &[Byte::from(0x8D), Byte::from(0x8D), Byte::from(0x8D)],
            0xFF,
        );
        case(
            &[
                Byte::from(0x8D),
                Byte::from(0x8D),
                Byte::from(0x8D),
                Byte::from(0x8D),
            ],
            0xFF,
        );
    }

    #[test]
    fn word_conversion_ciphertext_unsigned() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();

        let case = |bytes: &[u8]| {
            let bytes_enc = bytes
                .iter()
                .map(|x| {
                    Byte::try_from(
                        UInt::<8, L1GlweCiphertext>::encrypt_secret(*x as u64, &enc, &sk).bits,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();

            let actual = Word::try_from_bytes(&bytes_enc, Extend::Zero, &enc).unwrap();

            for (byte, actual) in bytes.iter().zip(actual.0.iter()).take(4) {
                let b = UInt::<8, _>::from_bits_shallow(actual.clone().unwrap_ciphertext());
                let actual = b.decrypt(&enc, &sk) as u8;
                assert_eq!(*byte, actual);
            }

            for actual in actual.0.iter().skip(bytes.len()) {
                let byte = UInt::<8, _>::from_bits_shallow(actual.clone().unwrap_ciphertext());
                let actual = byte.decrypt(&enc, &sk) as u8;
                assert_eq!(0, actual);
            }
        };

        case(&[0x8D]);
        case(&[0x8D, 0x8D]);
        case(&[0x8D, 0x8D, 0x8D]);
        case(&[0x8D, 0x8D, 0x8D, 0x8D]);
    }

    #[test]
    fn word_conversion_ciphertext_signed() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();

        let case = |bytes: &[u8]| {
            let bytes_enc = bytes
                .iter()
                .map(|x| {
                    Byte::try_from(
                        UInt::<8, L1GlweCiphertext>::encrypt_secret(*x as u64, &enc, &sk).bits,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();

            let actual = Word::try_from_bytes(&bytes_enc, Extend::Signed, &enc).unwrap();

            for (byte, actual) in bytes.iter().zip(actual.0.iter()).take(4) {
                let b = UInt::<8, _>::from_bits_shallow(actual.clone().unwrap_ciphertext());
                let actual = b.decrypt(&enc, &sk) as u8;
                assert_eq!(*byte, actual);
            }

            for actual in actual.0.iter().skip(bytes.len()) {
                let byte = UInt::<8, _>::from_bits_shallow(actual.clone().unwrap_ciphertext());
                let actual = byte.decrypt(&enc, &sk) as u8;
                assert_eq!(0xFF, actual);
            }
        };

        case(&[0x8D]);
        case(&[0x8D, 0x8D]);
        case(&[0x8D, 0x8D, 0x8D]);
        case(&[0x8D, 0x8D, 0x8D, 0x8D]);
    }

    #[test]
    fn can_allocate_and_load_type() {
        let val = 0x12345678u32;

        let memory = Memory::new_default_stack();

        let ptr = memory.try_allocate_type(&val).unwrap();
        let actual: u32 = memory.try_load_type(ptr).unwrap();

        assert_eq!(val, actual);
    }

    #[test]
    fn can_allocate_and_load_encrypted_type() {
        let sk = get_secret_keys_128();
        let enc = get_encryption_128();

        let val = 0x12345678u32;
        let val_enc = UInt::<32, L1GlweCiphertext>::encrypt_secret(0x12345678, &enc, &sk);

        let memory = Memory::new_default_stack();

        let ptr = memory.try_allocate_type(&val_enc).unwrap();
        let actual: UInt<32, L1GlweCiphertext> = memory.try_load_type(ptr).unwrap();

        assert_eq!(actual.decrypt(&enc, &sk) as u32, val);
    }
}
