use std::sync::Arc;

use concurrency::AtomicRefCell;
use mux_circuits::{MuxCircuit, bitshift::bitshift};
use parasol_runtime::{FheCircuit, L1GlweCiphertext};

use crate::{
    Ciphertext, Error, FheProcessor, Register, Result,
    proc::DispatchIsaOp,
    register_to_l1glwe_by_trivial_lift,
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

use super::make_parent_op;

fn rotate_right_arbitrary_width(val: u128, shift: u128, width: u32) -> u128 {
    let mask = (0x1 << width) - 1;

    let left = val << (width as u128 - shift);
    let right = val >> shift;

    (left | right) & mask
}

fn rotate_left_arbitrary_width(val: u128, shift: u128, width: u32) -> u128 {
    let mask = (0x1 << width) - 1;

    let left = val << shift;
    let right = val >> (width as u128 - shift);

    (left | right) & mask
}

fn encrypted_value_plain_shift(
    c: &[Arc<AtomicRefCell<L1GlweCiphertext>>],
    shift: u32,
    l1glwe_zero: &L1GlweCiphertext,
    right: bool,
    zero: bool,
) -> Vec<Arc<AtomicRefCell<L1GlweCiphertext>>> {
    let mut result = c.to_owned();

    // The processor is little endian, so a right shift is a left rotation.
    if right {
        result.rotate_left(shift as usize);
    } else {
        result.rotate_right(shift as usize);
    }
    if zero {
        for i in 0..shift as usize {
            let ix = if right { result.len() - i - 1 } else { i };
            result[ix] = Arc::new(AtomicRefCell::new(l1glwe_zero.clone()));
        }
    }
    result
}

// (val, shift, width) -> u128
type ShiftOperation = fn(u128, u128, u32) -> u128;

// (c, shift, l1glwe_zero) -> Vec<Arc<AtomicRefCell<L1GlweCiphertext>>>
type ShiftOperationCiphertext = fn(
    &[Arc<AtomicRefCell<L1GlweCiphertext>>],
    u32,
    &L1GlweCiphertext,
) -> Vec<Arc<AtomicRefCell<L1GlweCiphertext>>>;

impl FheProcessor {
    #[allow(clippy::too_many_arguments)]
    fn shift_operation(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        src: RobEntryRef<Register>,
        shift: RobEntryRef<Register>,
        _instruction_id: usize,
        _pc: usize,
        plain_operation: ShiftOperation,
        plain_shift: ShiftOperationCiphertext,
        circuit_gen: fn(usize, usize) -> MuxCircuit,
    ) {
        let mut shift_impl = || -> Result<()> {
            unwrap_registers!([self.constant_pool] (mut dst) (src) (shift));

            match (src, shift) {
                (
                    Register::Plaintext { val, width },
                    Register::Plaintext {
                        val: shift,
                        width: _,
                    },
                ) => {
                    *dst = Register::Plaintext {
                        val: plain_operation(*val, *shift, *width),
                        width: *width,
                    };

                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                (
                    Register::Ciphertext(Ciphertext::L1Glwe { data: c }),
                    Register::Plaintext {
                        val: shift,
                        width: _,
                    },
                ) => {
                    let output = plain_shift(c, *shift as u32, &self.aux_data.l1glwe_zero);

                    *dst = Register::Ciphertext(Ciphertext::L1Glwe { data: output });

                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                (_, Register::Ciphertext(Ciphertext::L1Glwe { data: c_shift })) => {
                    let c = register_to_l1glwe_by_trivial_lift(
                        src,
                        &self.aux_data.l1glwe_zero,
                        &self.aux_data.l1glwe_one,
                    )?;

                    let input_width = c.len();
                    let shift_width = c_shift.len();

                    let mut graph = FheCircuit::new();
                    let circuit = circuit_gen(input_width, shift_width);

                    // This circuit is big endian
                    let inputs = c
                        .iter()
                        .rev()
                        .chain(c_shift.iter().rev())
                        .cloned()
                        .collect::<Vec<_>>();

                    let mut output = graph.insert_mux_circuit_and_connect_inputs(
                        &circuit,
                        &inputs,
                        &self.aux_data.enc,
                    );

                    // The outputs are in big endian
                    output.reverse();

                    let parent_op = make_parent_op(&retirement_info);

                    self.aux_data
                        .uop_processor
                        .spawn_graph(&graph, &self.aux_data.flow, parent_op);

                    *dst = Register::Ciphertext(Ciphertext::L1Glwe { data: output });
                }
                _ => return Err(Error::RegisterCiphertextMismatch),
            }

            Ok(())
        };

        if let Err(e) = shift_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }

    /// Execute an and instruction, where each element in the vector is a bit.
    pub fn shr(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        src: RobEntryRef<Register>,
        shift: RobEntryRef<Register>,
        instruction_id: usize,
        pc: usize,
    ) {
        self.shift_operation(
            retirement_info,
            dst,
            src,
            shift,
            instruction_id,
            pc,
            |val, shift, _| val >> shift,
            |c, shift, l1glwe_zero| encrypted_value_plain_shift(c, shift, l1glwe_zero, true, true),
            |inputs, shift_size| bitshift(inputs as u16, shift_size as u16, true, true),
        )
    }

    pub fn shl(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        src: RobEntryRef<Register>,
        shift: RobEntryRef<Register>,
        instruction_id: usize,
        pc: usize,
    ) {
        self.shift_operation(
            retirement_info,
            dst,
            src,
            shift,
            instruction_id,
            pc,
            |val, shift, _| val << shift,
            |c, shift, l1glwe_zero| encrypted_value_plain_shift(c, shift, l1glwe_zero, false, true),
            |inputs, shift_size| bitshift(inputs as u16, shift_size as u16, false, true),
        )
    }

    pub fn rotr(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        src: RobEntryRef<Register>,
        shift: RobEntryRef<Register>,
        instruction_id: usize,
        pc: usize,
    ) {
        self.shift_operation(
            retirement_info,
            dst,
            src,
            shift,
            instruction_id,
            pc,
            rotate_right_arbitrary_width,
            |c, shift, l1glwe_zero| encrypted_value_plain_shift(c, shift, l1glwe_zero, true, false),
            |inputs, shift_size| bitshift(inputs as u16, shift_size as u16, true, false),
        )
    }

    pub fn rotl(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        src: RobEntryRef<Register>,
        shift: RobEntryRef<Register>,
        instruction_id: usize,
        pc: usize,
    ) {
        self.shift_operation(
            retirement_info,
            dst,
            src,
            shift,
            instruction_id,
            pc,
            rotate_left_arbitrary_width,
            |c, shift, l1glwe_zero| {
                encrypted_value_plain_shift(c, shift, l1glwe_zero, false, false)
            },
            |inputs, shift_size| bitshift(inputs as u16, shift_size as u16, false, false),
        )
    }
}
