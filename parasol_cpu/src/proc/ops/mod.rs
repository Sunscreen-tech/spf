use std::sync::Arc;

use crate::{Ciphertext, proc::DispatchIsaOp, tomasulo::tomasulo_processor::RetirementInfo};

use mux_circuits::convert_value_to_bits;
use parasol_concurrency::AtomicRefCell;
use parasol_runtime::{
    CiphertextType, CompletionHandler, FheCircuit, FheOp, L1GlweCiphertext,
    insert_ciphertext_conversion,
};
use petgraph::stable_graph::NodeIndex;

use super::fhe_processor::FheProcessor;

mod add;
mod and;
mod bitshift;
mod casting;
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

pub fn make_parent_op(retirement_info: &RetirementInfo<DispatchIsaOp>) -> Arc<CompletionHandler> {
    let retirement_info = retirement_info.clone();

    Arc::new(CompletionHandler::new(move || {
        FheProcessor::retire(&retirement_info, Ok(()))
    }))
}

pub(crate) fn is_invalid_load_store_alignment(base_addr: u32, width: u32) -> bool {
    base_addr % width != 0 || width > 16 || !width.is_power_of_two() || width == 0
}

#[macro_export]
#[doc(hidden)]
macro_rules! unwrap_registers {
    ((mut $reg:ident) $($rest:tt)*) => {
        let mut $reg = $reg.entry_mut()?;
        let $reg = std::ops::DerefMut::deref_mut(&mut *$reg);
        unwrap_registers!($($rest)*);
    };
    (($reg:ident) $($rest:tt)*) => {
        let $reg = $reg.entry();
        let $reg = std::ops::Deref::deref(&*$reg);
        unwrap_registers!($($rest)*);
    };
    () => {

    };
}
