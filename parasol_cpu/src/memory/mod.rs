// TODO: Remove
#![allow(unused)]

use std::sync::{Arc, Mutex};

use crate::{Error, Result};
use elf::{ElfBytes, endian::LittleEndian, file::Class};
use parasol_concurrency::AtomicRefCell;
use parasol_runtime::L1GlweCiphertext;

/// log2(bytes_per_page)
const LOG2_PAGE_SIZE: u32 = 12;

/// The number of bytes in a page.
const PAGE_SIZE: u32 = 0x1 << LOG2_PAGE_SIZE;

// The top bits of a pointer indicate the page id.
const PAGE_OFFSET_MASK: u32 = PAGE_SIZE - 1;

// The bottom bits indicate the byte offset.
const PAGE_ID_MASK: u32 = !PAGE_OFFSET_MASK;

// The total number of pages that fit in the 32-bit address space.
const TOTAL_PAGES: u32 = 0x1 << (32 - LOG2_PAGE_SIZE);

// ABI version changes:
// 1:
//   - Organized instructions into groupings
//   - Added rotl, rotr, neg, xor, addc, subb
//   - Note that addc and subb are not currently implemented in the backend, but
//     they do have defined opcodes.
pub const SUPPORTED_ABI_VERSION: u8 = 1;

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
/// A 32-bit pointer.
pub struct Ptr32(u32);

impl From<u32> for Ptr32 {
    fn from(value: u32) -> Self {
        Self(value)
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
}

pub struct Memory {
    pages: Mutex<Vec<Option<Page>>>,
}

impl Memory {
    pub fn new_from_elf(elf_data: &[u8]) -> Result<Self> {
        let memory = Self {
            pages: Mutex::new(vec![None; TOTAL_PAGES as usize]),
        };

        let elf = ElfBytes::<LittleEndian>::minimal_parse(elf_data)?;

        let abi_version = elf.ehdr.abiversion;

        if elf.ehdr.class != Class::ELF32 {
            return Err(Error::ElfNotElf32);
        }

        let segments = elf.segments().ok_or(Error::ElfNoSegmentTable)?;

        for segment in segments {
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

            // TODO: WTF do we do with zero-size segments?
            let len = if segment.p_memsz == 0 {
                1
            } else {
                segment.p_memsz as u32
            };

            // The ELF specification allows p_memsz > p_filesz, which should be filled with zeros.
            // However, page allocation zeros the full region, so this case is already handled
            // for us.
            memory.try_allocate_at(mem_start, len)?;

            // Copy the bytes from the ELF file into memory
            for (i, (f, m)) in (file_start.0..file_end.0)
                .zip(mem_start.0..mem_end.0)
                .enumerate()
            {
                let byte = elf_data
                    .get(f as usize)
                    .ok_or(Error::ElfByteOutofBounds(f))?;

                memory.try_store(m.into(), Byte::Plaintext(*byte))?;
            }
        }

        Ok(memory)
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
            if pages[i].is_none() {
                pages[i] = Some(Page::allocate())
            }
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

                {
                    p.store_byte(page_offset as usize, data);
                };
                Ok(())
            }
            None => Err(Error::AccessViolation(virtual_address.0)),
        }
    }

    /// Allocate a contiguous virtual address region of at least `len` bytes. This also
    /// allocates the backing pages.
    pub fn allocate(&self, len: u32) -> Result<Ptr32> {
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
}

#[derive(Clone)]
pub enum Byte {
    Plaintext(u8),
    Ciphertext(Vec<Arc<AtomicRefCell<L1GlweCiphertext>>>),
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
        let ptr_plain = memory.allocate(32).unwrap();
        let ptr_ct = memory.allocate(32).unwrap();

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
        let mask = PAGE_SIZE - 1;
        let mask = !mask;

        let id = Page::page_id_from_pointer(addr.into());

        assert_eq!(id, (addr & mask) >> LOG2_PAGE_SIZE);
    }
}
