use std::collections::HashMap;

use crate::{
    DispatchIsaOp::{self, *},
    Register,
    tomasulo::registers::RobEntryRef,
};

pub(crate) struct GasModel {
    per_op_per_width_cost: HashMap<&'static str, [u32; 4]>,
    per_op_per_bi_width_cost: HashMap<&'static str, [[u32; 4]; 4]>,
}

fn is_register_ciphertext(reg: &RobEntryRef<Register>) -> bool {
    match reg {
        RobEntryRef::Id(e) | RobEntryRef::IdMut(e) => e.entry().is_ciphertext(),
    }
}

fn register_width_to_index(reg: &RobEntryRef<Register>) -> usize {
    match reg {
        RobEntryRef::Id(e) | RobEntryRef::IdMut(e) => match e.entry().width().saturating_sub(1) {
            0..8 => 0,
            8..16 => 1,
            16..32 => 2,
            32..64 => 3,
            64.. => unimplemented!("No support for bit width over 64"),
        },
    }
}

impl GasModel {
    pub(crate) fn new() -> Self {
        let mut per_op_per_width_cost = HashMap::new();
        let mut per_op_per_bi_width_cost = HashMap::new();

        // TODO: confirm the numbers after redoing shift
        per_op_per_width_cost.insert(stringify!(Not), [380, 720, 1_450, 7_500]);
        per_op_per_width_cost.insert(stringify!(Neg), [500, 930, 2_480, 120_000]);
        per_op_per_width_cost.insert(stringify!(And), [800, 1_650, 6_000, 29_000]);
        per_op_per_width_cost.insert(stringify!(Or), [810, 1_770, 2_810, 17_400]);
        per_op_per_width_cost.insert(stringify!(Xor), [650, 1_260, 2_650, 29_400]);
        per_op_per_width_cost.insert(stringify!(Add), [940, 2_080, 65_000, 350_000]);
        per_op_per_width_cost.insert(stringify!(Sub), [1_020, 2_240, 104_000, 408_000]);
        per_op_per_width_cost.insert(stringify!(CmpEq), [740, 1_480, 3_860, 9_100]);
        per_op_per_width_cost.insert(stringify!(CmpGt), [840, 1_820, 6_800, 56_000]);
        per_op_per_width_cost.insert(stringify!(CmpGe), [920, 2_500, 14_000, 13_400]);
        per_op_per_width_cost.insert(stringify!(CmpLt), [820, 1_880, 4_800, 10_880]);
        per_op_per_width_cost.insert(stringify!(CmpLe), [900, 2_480, 21_000, 12_400]);
        per_op_per_width_cost.insert(stringify!(CmpGtS), [880, 2_180, 3_180, 12_800]);
        per_op_per_width_cost.insert(stringify!(CmpGeS), [860, 1_820, 3_100, 12_800]);
        per_op_per_width_cost.insert(stringify!(CmpLtS), [840, 2_040, 18_800, 19_000]);
        per_op_per_width_cost.insert(stringify!(CmpLeS), [860, 1_800, 10_600, 12_600]);
        per_op_per_width_cost.insert(stringify!(Mul), [1_740, 116_000, 468_000, 2_240_000]);
        per_op_per_width_cost.insert(stringify!(AddC), [1_000, 2_200, 69_000, 354_000]);
        per_op_per_width_cost.insert(stringify!(SubB), [1_000, 2_240, 67_300, 407_000]);
        per_op_per_width_cost.insert(stringify!(Cmux), [580, 1_080, 1_980, 3_820]);

        per_op_per_bi_width_cost.insert(
            stringify!(Shr),
            [
                [58_600, 1_000_000_000, 1_000_000_000, 1_000_000_000],
                [53_060_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
                [1_000_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
                [1_000_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
            ],
        );
        per_op_per_bi_width_cost.insert(
            stringify!(Shra),
            [
                [58_860, 1_000_000_000, 1_000_000_000, 1_000_000_000],
                [44_900_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
                [1_000_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
                [1_000_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
            ],
        );
        per_op_per_bi_width_cost.insert(
            stringify!(Shl),
            [
                [58_840, 1_000_000_000, 1_000_000_000, 1_000_000_000],
                [53_500_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
                [1_000_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
                [1_000_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
            ],
        );
        per_op_per_bi_width_cost.insert(
            stringify!(Rotr),
            [
                [126_620, 1_000_000_000, 1_000_000_000, 1_000_000_000],
                [396_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
                [1_000_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
                [1_000_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
            ],
        );
        per_op_per_bi_width_cost.insert(
            stringify!(Rotl),
            [
                [126_620, 1_000_000_000, 1_000_000_000, 1_000_000_000],
                [398_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
                [1_000_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
                [1_000_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
            ],
        );

        Self {
            per_op_per_width_cost,
            per_op_per_bi_width_cost,
        }
    }

    fn figure_out_gas(
        &self,
        check_regs: &[&RobEntryRef<Register>],
        data_reg: &RobEntryRef<Register>,
        op: &DispatchIsaOp,
    ) -> u32 {
        if check_regs.iter().any(|x| is_register_ciphertext(x)) {
            self.per_op_per_width_cost[op.instr_name()][register_width_to_index(data_reg)]
        } else {
            1
        }
    }

    fn figure_out_gas_bi(
        &self,
        check_regs: &[&RobEntryRef<Register>],
        data_reg_pri: &RobEntryRef<Register>,
        data_reg_sec: &RobEntryRef<Register>,
        op: &DispatchIsaOp,
    ) -> u32 {
        if check_regs.iter().any(|x| is_register_ciphertext(x)) {
            self.per_op_per_bi_width_cost[op.instr_name()][register_width_to_index(data_reg_pri)]
                [register_width_to_index(data_reg_sec)]
        } else {
            1
        }
    }

    pub(crate) fn compute_gas(&self, op: &DispatchIsaOp) -> u32 {
        match op {
            // return assigned zero cost
            Ret() => 0,

            // instructions that have trivial cost: either they do not deal with any ciphertext at all
            // or they don't compute on ciphertext content (just treat them as vector of opaque objects)
            Load(..) | LoadI(..) | Store(..) | BranchNonZero(..) | BranchZero(..) | Branch(..)
            | Move(..) | Dbg(..) | Sext(..) | Zext(..) | Trunc(..) => 1,

            // Not has only one input and the cost is non-trivial if that input is ciphertext
            Not(_, input) => self.figure_out_gas(&[input], input, op),

            // Neg has only one input and the cost is non-trivial if that input is ciphertext
            Neg(_, input) => self.figure_out_gas(&[input], input, op),

            // And has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            And(_, input1, input2) => self.figure_out_gas(&[input1, input2], input1, op),

            // Or has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            Or(_, input1, input2) => self.figure_out_gas(&[input1, input2], input1, op),

            // Xor has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            Xor(_, input1, input2) => self.figure_out_gas(&[input1, input2], input1, op),

            // Add has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            Add(_, input1, input2) => self.figure_out_gas(&[input1, input2], input1, op),

            // Sub has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            Sub(_, input1, input2) => self.figure_out_gas(&[input1, input2], input1, op),

            // CmpEq has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpEq(_, input1, input2) => self.figure_out_gas(&[input1, input2], input1, op),

            // CmpGt has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpGt(_, input1, input2) => self.figure_out_gas(&[input1, input2], input1, op),

            // CmpGe has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpGe(_, input1, input2) => self.figure_out_gas(&[input1, input2], input1, op),

            // CmpLt has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpLt(_, input1, input2) => self.figure_out_gas(&[input1, input2], input1, op),

            // CmpLe has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpLe(_, input1, input2) => self.figure_out_gas(&[input1, input2], input1, op),

            // CmpGtS has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpGtS(_, input1, input2) => self.figure_out_gas(&[input1, input2], input1, op),

            // CmpGeS has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpGeS(_, input1, input2) => self.figure_out_gas(&[input1, input2], input1, op),

            // CmpLtS has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpLtS(_, input1, input2) => self.figure_out_gas(&[input1, input2], input1, op),

            // CmpLeS has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpLeS(_, input1, input2) => self.figure_out_gas(&[input1, input2], input1, op),

            // Mul has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            Mul(_, input1, input2) => self.figure_out_gas(&[input1, input2], input1, op),

            // Shr has two inputs that are not interchangeable and the cost is non-trivial if the second input is ciphertext
            // (where the first one will be lifted to ciphertext if not already)
            Shr(_, input1, input2) => self.figure_out_gas_bi(&[input2], input1, input2, op),

            // Shra has two inputs that are not interchangeable and the cost is non-trivial if the second input is ciphertext
            // (where the first one will be lifted to ciphertext if not already)
            Shra(_, input1, input2) => self.figure_out_gas_bi(&[input2], input1, input2, op),

            // Shl has two inputs that are not interchangeable and the cost is non-trivial if the second input is ciphertext
            // (where the first one will be lifted to ciphertext if not already)
            Shl(_, input1, input2) => self.figure_out_gas_bi(&[input2], input1, input2, op),

            // Rotr has two inputs that are not interchangeable and the cost is non-trivial if the second input is ciphertext
            // (where the first one will be lifted to ciphertext if not already)
            Rotr(_, input1, input2) => self.figure_out_gas_bi(&[input2], input1, input2, op),

            // Rotl has two inputs that are not interchangeable and the cost is non-trivial if the second input is ciphertext
            // (where the first one will be lifted to ciphertext if not already)
            Rotl(_, input1, input2) => self.figure_out_gas_bi(&[input2], input1, input2, op),

            // AddC has three inputs that are not interchangeable and the cost is non-trivial if any input is ciphertext
            // (where the other ones will be lifted to ciphertext if not already), note first two input widths must be the same
            // while last input width must be one
            AddC(_, _, input1, input2, input3) => {
                self.figure_out_gas(&[input1, input2, input3], input1, op)
            }

            // SubB has three inputs that are not interchangeable and the cost is non-trivial if any input is ciphertext
            // (where the other ones will be lifted to ciphertext if not already), note first two input widths must be the same
            // while last input width must be one
            SubB(_, _, input1, input2, input3) => {
                self.figure_out_gas(&[input1, input2, input3], input1, op)
            }

            // Cmux has three inputs that are not interchangeable and the cost is non-trivial if the first input is ciphertext
            // (where the other ones will be lifted to ciphertext if not already), note last two input widths must be the same
            // while first input width must be one
            Cmux(_, input1, input2, _input3) => self.figure_out_gas(&[input1], input2, op),
        }
    }
}
