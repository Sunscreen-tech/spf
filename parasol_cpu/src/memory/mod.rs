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

        for s in segments {
            if s.p_memsz > u32::MAX as u64 || s.p_vaddr > u32::MAX as u64 {
                // Should be unreachable if elf crate is correct.
                return Err(Error::ElfUnreachable);
            }

            let len = s.p_memsz as u32;
            let vaddr = s.p_vaddr as u32;

            dbg!((vaddr, len));
            dbg!(s.p_type);

            //memory.try_allocate_at(vaddr, len)?;
        }

        Ok(memory)
    }

    fn try_allocate_at(&self, virtual_address: u32, len: u32) -> Result<()> {
        let len = len.next_multiple_of(PAGE_SIZE);
        let num_pages = (len / PAGE_SIZE) as usize;
        let start_page_id = Page::page_id_from_pointer(virtual_address) as usize;
        let end_page_id = (start_page_id + num_pages - 1);

        let mut pages = self.pages.lock().unwrap();

        // Make sure none of the pages are in use.
        if (start_page_id..=end_page_id).any(|i| pages[i].is_some()) {
            return Err(Error::VirtualAddressInUse);
        }

        for i in start_page_id..=end_page_id {
            pages[i] = Some(Page::allocate())
        }

        Ok(())
    }
}

#[derive(Clone)]
enum Byte {
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

    pub fn page_id_from_pointer(ptr: u32) -> u32 {
        (ptr & PAGE_OFFSET_MASK) >> LOG2_PAGE_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARDIO_O: &[u8] = include_bytes!("test_data/cardio.so");

    #[test]
    fn can_create_memory() {
        let _ = Memory::new_from_elf(CARDIO_O).unwrap();
    }
}
