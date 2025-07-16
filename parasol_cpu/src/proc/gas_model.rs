use std::collections::HashMap;

use crate::{
    DispatchIsaOp::{self, *},
    Register,
    tomasulo::registers::RobEntryRef,
};

pub(crate) struct GasModel {
    per_op_per_width_cost: HashMap<&'static str, [u32; 4]>,
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

        // TODO: benchmark to replace the numbers
        per_op_per_width_cost.insert(stringify!(Not), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(Neg), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(And), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(Or), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(Xor), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(Add), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(Sub), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(CmpEq), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(CmpGt), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(CmpGe), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(CmpLt), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(CmpLe), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(CmpGtS), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(CmpGeS), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(CmpLtS), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(CmpLeS), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(Mul), [500_000, 500_000, 500_000, 500_000]);
        per_op_per_width_cost.insert(stringify!(Shr), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(Shra), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(Shl), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(Rotr), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(Rotl), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(AddC), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(SubB), [100_000, 100_000, 100_000, 100_000]);
        per_op_per_width_cost.insert(stringify!(Cmux), [100_000, 100_000, 100_000, 100_000]);

        Self {
            per_op_per_width_cost,
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
            Not(_, input) => {
                if is_register_ciphertext(input) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input)]
                } else {
                    1
                }
            }

            // Neg has only one input and the cost is non-trivial if that input is ciphertext
            Neg(_, input) => {
                if is_register_ciphertext(input) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input)]
                } else {
                    1
                }
            }

            // And has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            And(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // Or has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            Or(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // Xor has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            Xor(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // Add has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            Add(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // Sub has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            Sub(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // CmpEq has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpEq(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // CmpGt has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpGt(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // CmpGe has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpGe(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // CmpLt has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpLt(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // CmpLe has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpLe(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // CmpGtS has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpGtS(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // CmpGeS has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpGeS(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // CmpLtS has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpLtS(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // CmpLeS has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            CmpLeS(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // Mul has two inputs that are interchangeable and the cost is non-trivial if either input is ciphertext
            // (where the other one will be lifted to ciphertext if not already), note their widths must be the same
            Mul(_, input1, input2) => {
                if is_register_ciphertext(input1) || is_register_ciphertext(input2) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // Shr has two inputs that are not interchangeable and the cost is non-trivial if the second input is ciphertext
            // (where the first one will be lifted to ciphertext if not already)
            Shr(_, _, input) => {
                if is_register_ciphertext(input) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input)]
                } else {
                    1
                }
            }

            // Shra has two inputs that are not interchangeable and the cost is non-trivial if the second input is ciphertext
            // (where the first one will be lifted to ciphertext if not already)
            Shra(_, _, input) => {
                if is_register_ciphertext(input) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input)]
                } else {
                    1
                }
            }

            // Shl has two inputs that are not interchangeable and the cost is non-trivial if the second input is ciphertext
            // (where the first one will be lifted to ciphertext if not already)
            Shl(_, _, input) => {
                if is_register_ciphertext(input) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input)]
                } else {
                    1
                }
            }

            // Rotr has two inputs that are not interchangeable and the cost is non-trivial if the second input is ciphertext
            // (where the first one will be lifted to ciphertext if not already)
            Rotr(_, _, input) => {
                if is_register_ciphertext(input) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input)]
                } else {
                    1
                }
            }

            // Rotl has two inputs that are not interchangeable and the cost is non-trivial if the second input is ciphertext
            // (where the first one will be lifted to ciphertext if not already)
            Rotl(_, _, input) => {
                if is_register_ciphertext(input) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input)]
                } else {
                    1
                }
            }

            // AddC has three inputs that are not interchangeable and the cost is non-trivial if any input is ciphertext
            // (where the other ones will be lifted to ciphertext if not already), note first two input widths must be the same
            // while last input width must be one
            AddC(_, _, input1, input2, input3) => {
                if is_register_ciphertext(input1)
                    || is_register_ciphertext(input2)
                    || is_register_ciphertext(input3)
                {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // SubB has three inputs that are not interchangeable and the cost is non-trivial if any input is ciphertext
            // (where the other ones will be lifted to ciphertext if not already), note first two input widths must be the same
            // while last input width must be one
            SubB(_, _, input1, input2, input3) => {
                if is_register_ciphertext(input1)
                    || is_register_ciphertext(input2)
                    || is_register_ciphertext(input3)
                {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input1)]
                } else {
                    1
                }
            }

            // Cmux has three inputs that are not interchangeable and the cost is non-trivial if the first input is ciphertext
            // (where the other ones will be lifted to ciphertext if not already), note last two input widths must be the same
            // while first input width must be one
            Cmux(_, input1, input2, _input3) => {
                if is_register_ciphertext(input1) {
                    self.per_op_per_width_cost[op.instr_name()][register_width_to_index(input2)]
                } else {
                    1
                }
            }
        }
    }
}
