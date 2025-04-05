use std::{collections::HashSet, sync::Arc};

use crate::{
    tomasulo::registers::RobEntryRef, unwrap_registers, Buffer, CiphertextPtr, Error,
    FheProcessorConstantPool, PlainOffsetCtPtr, PlaintextPtr, PtrRegister, Result,
};

#[allow(clippy::too_many_arguments)]
/// Creates a PtrRegister to the buffer at the given index.
pub fn assign_io(
    constant_pool: &Arc<FheProcessorConstantPool>,
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

    unwrap_registers!([constant_pool] (mut dst));

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
