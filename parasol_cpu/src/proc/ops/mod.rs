use std::sync::Arc;

use crate::{
    proc::DispatchIsaOp, tomasulo::tomasulo_processor::RetirementInfo, Ciphertext, Error,
    FheProcessor, Result,
};

use concurrency::AtomicRefCell;
use mux_circuits::convert_value_to_bits;
use parasol_runtime::{
    insert_ciphertext_conversion, CiphertextType, CompletionHandler, FheCircuit, FheOp,
    L1GlweCiphertext,
};
use petgraph::stable_graph::NodeIndex;

mod input_output;
pub use input_output::*;
mod add;
mod and;
mod bitshift;
mod casting;
mod cea;
mod cmux;
mod comparisons;
mod load;
mod loadi;
mod mul;
mod neg;
mod not;
mod or;
mod store;
mod sub;
mod xor;

/// Insert the given `input` ciphertext into the `graph`, inserting conversions
/// to the desired `dst` type. Returns the node indices of the converted
/// cipertext bits.
pub fn insert_ciphertext_inputs(
    graph: &mut FheCircuit,
    input: &Ciphertext,
    dst: CiphertextType,
) -> Vec<NodeIndex> {
    // We mutate graph inside `map`, which is kinda gross, but not
    // as gross as a dozen dozen.
    match input {
        Ciphertext::L0Lwe { data } => data
            .iter()
            .map(|x| {
                let input_node = graph.add_node(FheOp::InputLwe0(x.clone()));

                insert_ciphertext_conversion(
                    graph,
                    input_node,
                    CiphertextType::L0LweCiphertext,
                    dst,
                )
            })
            .collect(),
        Ciphertext::L1Ggsw { data } => data
            .iter()
            .map(|x| {
                let input_node = graph.add_node(FheOp::InputGgsw1(x.clone()));

                insert_ciphertext_conversion(
                    graph,
                    input_node,
                    CiphertextType::L1GgswCiphertext,
                    dst,
                )
            })
            .collect(),
        Ciphertext::L1Glwe { data } => data
            .iter()
            .map(|x| {
                let input_node = graph.add_node(FheOp::InputGlwe1(x.clone()));

                insert_ciphertext_conversion(
                    graph,
                    input_node,
                    CiphertextType::L1GlweCiphertext,
                    dst,
                )
            })
            .collect(),
        Ciphertext::L1Lwe { data } => data
            .iter()
            .map(|x| {
                let input_node = graph.add_node(FheOp::InputLwe1(x.clone()));

                insert_ciphertext_conversion(
                    graph,
                    input_node,
                    CiphertextType::L1LweCiphertext,
                    dst,
                )
            })
            .collect(),
    }
}

/// Encrypts a multi-bit value using the given L1 GLWE ciphertexts.
pub(crate) fn trivially_encrypt_value_l1glwe(
    val: u128,
    width: u32,
    zero: &L1GlweCiphertext,
    one: &L1GlweCiphertext,
) -> Vec<Arc<AtomicRefCell<L1GlweCiphertext>>> {
    let bits = convert_value_to_bits(val, width);

    bits.into_iter()
        .map(|bit| {
            let encrypted_bit = if bit { one.clone() } else { zero.clone() };
            Arc::new(AtomicRefCell::new(encrypted_bit))
        })
        .collect()
}

/// Checks that the given offset is aligned to offset.next_power_of_two(),
/// it's in bounds, and that the width is sensible.
fn check_offset(
    width: u32,
    offset: u32,
    len: usize,
    instruction_id: usize,
    pc: usize,
) -> Result<u32> {
    let num_bytes = width.next_multiple_of(8) / 8;

    if num_bytes == 0 || num_bytes > 16 {
        return Err(Error::unsupported_width(instruction_id, pc));
    }

    if offset % num_bytes != 0 {
        return Err(Error::UnalignedAccess {
            inst_id: instruction_id,
            pc,
        });
    }

    if len > u32::MAX as usize {
        return Err(Error::out_of_range(instruction_id, pc));
    }

    if offset + num_bytes > len as u32 {
        return Err(Error::AccessViolation {
            inst_id: instruction_id,
            pc,
        });
    }

    Ok(num_bytes)
}

fn read_write_mask(bit_width: u32) -> u8 {
    let shift_amt = bit_width.next_multiple_of(8) - bit_width;
    0xFF >> shift_amt
}

pub fn make_parent_op(retirement_info: &RetirementInfo<DispatchIsaOp>) -> Arc<CompletionHandler> {
    let retirement_info = retirement_info.clone();

    Arc::new(CompletionHandler::new(move || {
        FheProcessor::retire(&retirement_info, Ok(()))
    }))
}

#[macro_export]
#[doc(hidden)]
macro_rules! unwrap_registers {
    ([$const_pool:expr] (mut $reg:ident) $($rest:tt)*) => {
        let mut $reg = $const_pool.register_mut(&$reg)?;
        let $reg = std::ops::DerefMut::deref_mut(&mut $reg);
        unwrap_registers!([$const_pool] $($rest)*);
    };
    ([$const_pool:expr] ($reg:ident) $($rest:tt)*) => {
        let $reg = $const_pool.register(&$reg);
        let $reg = std::ops::Deref::deref(&$reg);
        unwrap_registers!([$const_pool] $($rest)*);
    };
    ([$const_pool:expr]) => {

    };
}
