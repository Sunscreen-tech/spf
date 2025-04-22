use std::collections::HashSet;

use crate::{
    Buffer, CiphertextPtr, Error, PlainOffsetCtPtr, PlaintextPtr, PtrRegister, Result,
    tomasulo::registers::RobEntryRef, unwrap_registers,
};

#[allow(clippy::too_many_arguments)]
/// Creates a PtrRegister to the buffer at the given index.
pub fn assign_io(
    dst: RobEntryRef<PtrRegister>,
    buffers: &[Buffer],
    is_encrypted: bool,
    in_use: &mut HashSet<usize>,
    buffer_id: usize,
    program_counter: usize,
    instruction_count: usize,
) -> Result<()> {
    if in_use.contains(&buffer_id) {
        return Err(Error::aliasing_violation(
            instruction_count,
            program_counter,
            buffer_id,
        ));
    }

    in_use.insert(buffer_id);

    unwrap_registers!((mut dst));

    let buffer = buffers
        .get(buffer_id)
        .ok_or(Error::no_buffer(instruction_count, program_counter))?;

    match (is_encrypted, buffer) {
        (false, Buffer::Plaintext(buf)) => {
            *dst = PtrRegister::Plaintext(PlaintextPtr {
                base: buf.clone(),
                offset: 0,
                last_write: None,
            });
        }
        (true, Buffer::Ciphertext(buf)) => {
            *dst = PtrRegister::Ciphertext(CiphertextPtr::PlainOffset(PlainOffsetCtPtr {
                base: buf.clone(),
                offset: 0,
                last_write: None,
            }));
        }
        _ => {
            return Err(Error::BufferMismatch {
                inst_id: instruction_count,
                pc: program_counter,
            });
        }
    };

    Ok(())
}
