use mux_circuits::{
    MuxCircuit,
    comparisons::{compare_equal, compare_or_maybe_equal, compare_or_maybe_equal_signed},
};
use parasol_runtime::FheCircuit;

use crate::{
    Ciphertext, Register, Result, check_register_width,
    proc::{DispatchIsaOp, fhe_processor::FheProcessor},
    register_to_l1glwe_by_trivial_lift,
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

use super::make_parent_op;

fn to_signed(val: u128, width: u32) -> i128 {
    let sign = 1 << (width - 1);
    if sign & val == 0 {
        val as i128
    } else {
        (!((sign << 1) - 1) | val) as i128
    }
}

impl FheProcessor {
    #[allow(clippy::too_many_arguments)]
    fn comparison_operation(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: u32,
        operation: fn(u128, u32, u128, u32) -> bool,
        circuit_gen: fn(usize) -> MuxCircuit,
    ) {
        let mut comparison_impl = || -> Result<()> {
            unwrap_registers!((mut dst) (a) (b));

            check_register_width(a, b, instruction_id, pc)?;

            if let (
                Register::Plaintext {
                    val: val1,
                    width: width1,
                },
                Register::Plaintext {
                    val: val2,
                    width: width2,
                },
            ) = (a, b)
            {
                *dst = Register::Plaintext {
                    val: operation(*val1, *width1, *val2, *width2) as u128,
                    width: 1,
                };

                FheProcessor::retire(&retirement_info, Ok(()));
            } else {
                let c1 = register_to_l1glwe_by_trivial_lift(
                    a,
                    &self.aux_data.l1glwe_zero,
                    &self.aux_data.l1glwe_one,
                )?;

                let c2 = register_to_l1glwe_by_trivial_lift(
                    b,
                    &self.aux_data.l1glwe_zero,
                    &self.aux_data.l1glwe_one,
                )?;

                let width = a.width();

                let mut graph = FheCircuit::new();
                let circuit = circuit_gen(width);

                // interleave c1 and c2 as required by the definition of the and circuit.
                let inputs = c1
                    .iter()
                    .zip(c2.iter())
                    .flat_map(|(a, b)| vec![a.clone(), b.clone()])
                    .collect::<Vec<_>>();

                let output = graph.insert_mux_circuit_and_connect_inputs(
                    &circuit,
                    &inputs,
                    &self.aux_data.enc,
                );

                let parent_op = make_parent_op(&retirement_info);

                self.aux_data
                    .uop_processor
                    .spawn_graph(&graph, &self.aux_data.flow, parent_op);

                *dst = Register::Ciphertext(Ciphertext::L1Glwe { data: output });
            }

            Ok(())
        };

        if let Err(e) = comparison_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
    /// Execute an and instruction, where each element in the vector is a bit.
    pub fn equal(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: u32,
    ) {
        self.comparison_operation(
            retirement_info,
            dst,
            a,
            b,
            instruction_id,
            pc,
            |a, _, b, _| a == b,
            compare_equal,
        )
    }

    pub fn greater_than(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: u32,
    ) {
        self.comparison_operation(
            retirement_info,
            dst,
            a,
            b,
            instruction_id,
            pc,
            |a, _, b, _| a > b,
            |n| compare_or_maybe_equal(n, true, false),
        )
    }

    pub fn greater_than_or_equal(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: u32,
    ) {
        self.comparison_operation(
            retirement_info,
            dst,
            a,
            b,
            instruction_id,
            pc,
            |a, _, b, _| a >= b,
            |n| compare_or_maybe_equal(n, true, true),
        )
    }

    pub fn less_than(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: u32,
    ) {
        self.comparison_operation(
            retirement_info,
            dst,
            a,
            b,
            instruction_id,
            pc,
            |a, _, b, _| a < b,
            |n| compare_or_maybe_equal(n, false, false),
        )
    }

    pub fn less_than_or_equal(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: u32,
    ) {
        self.comparison_operation(
            retirement_info,
            dst,
            a,
            b,
            instruction_id,
            pc,
            |a, _, b, _| a <= b,
            |n| compare_or_maybe_equal(n, false, true),
        )
    }

    pub fn greater_than_signed(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: u32,
    ) {
        self.comparison_operation(
            retirement_info,
            dst,
            a,
            b,
            instruction_id,
            pc,
            |a, wa, b, wb| to_signed(a, wa) > to_signed(b, wb),
            |n| compare_or_maybe_equal_signed(n, true, false),
        )
    }

    pub fn greater_than_or_equal_signed(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: u32,
    ) {
        self.comparison_operation(
            retirement_info,
            dst,
            a,
            b,
            instruction_id,
            pc,
            |a, wa, b, wb| to_signed(a, wa) >= to_signed(b, wb),
            |n| compare_or_maybe_equal_signed(n, true, true),
        )
    }

    pub fn less_than_signed(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: u32,
    ) {
        self.comparison_operation(
            retirement_info,
            dst,
            a,
            b,
            instruction_id,
            pc,
            |a, wa, b, wb| to_signed(a, wa) < to_signed(b, wb),
            |n| compare_or_maybe_equal_signed(n, false, false),
        )
    }

    pub fn less_than_or_equal_signed(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: u32,
    ) {
        self.comparison_operation(
            retirement_info,
            dst,
            a,
            b,
            instruction_id,
            pc,
            |a, wa, b, wb| to_signed(a, wa) <= to_signed(b, wb),
            |n| compare_or_maybe_equal_signed(n, false, true),
        )
    }
}
