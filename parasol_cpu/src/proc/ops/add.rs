use parasol_runtime::circuits::add::add_circuit;

use crate::{
    Ciphertext, Error, FheProcessor, Register, Result, check_register_width,
    proc::{DispatchIsaOp, ops::make_parent_op},
    register_to_l1glwe_by_trivial_lift,
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

impl FheProcessor {
    /// Execute a load instruction.
    pub fn add(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: usize,
    ) {
        let mut add_impl = || -> Result<()> {
            unwrap_registers!((mut dst) (a) (b));

            check_register_width(a, b, instruction_id, pc)?;

            if let (
                Register::Plaintext {
                    val: val1,
                    width: width1,
                },
                Register::Plaintext {
                    val: val2,
                    width: _,
                },
            ) = (a, b)
            {
                let mask = (0x1 << width1) - 1;

                *dst = Register::Plaintext {
                    val: val1.wrapping_add(*val2) & mask,
                    width: *width1,
                };

                FheProcessor::retire(&retirement_info, Ok(()));
            } else {
                // all other cases will need to convert the registers to l1 glwe ciphertexts,
                // so we'll handle them together.
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

                let (graph, output) = add_circuit(a.width(), &c1, &c2, None, &self.aux_data.enc);

                let parent_op = make_parent_op(&retirement_info);

                self.aux_data
                    .uop_processor
                    .spawn_graph(&graph, &self.aux_data.flow, parent_op);

                // There is a carry out bit that we will ignore
                *dst = Register::Ciphertext(Ciphertext::L1Glwe {
                    data: output[0..output.len() - 1].to_owned(),
                });
            }

            Ok(())
        };

        if let Err(e) = add_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_carry(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        carry_out: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        carry_in: RobEntryRef<Register>,
        instruction_id: usize,
        pc: usize,
    ) {
        let mut add_impl = || -> Result<()> {
            unwrap_registers!((mut dst) (mut carry_out) (a) (b) (carry_in));

            check_register_width(a, b, instruction_id, pc)?;

            // Check if the carry bit is a single bit
            if carry_in.width() != 1 {
                return Err(Error::WidthMismatch {
                    inst_id: instruction_id,
                    pc,
                });
            }

            // Handle the plaintext case separately, since all the ciphertext
            // cases need to convert at least one input to ciphertext.
            if let (
                Register::Plaintext { val: val1, width },
                Register::Plaintext {
                    val: val2,
                    width: _,
                },
                Register::Plaintext {
                    val: carry_in,
                    width: _,
                },
            ) = (a, b, carry_in)
            {
                let (sum, carry) = add_with_carry(*val1, *val2, *carry_in, *width);

                *dst = Register::Plaintext {
                    val: sum,
                    width: *width,
                };

                *carry_out = Register::Plaintext {
                    val: carry,
                    width: 1,
                };
                FheProcessor::retire(&retirement_info, Ok(()));
            } else {
                // All other cases will need to convert the registers to l1 glwe ciphertexts,
                // so we'll handle them together.
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
                let c_carry = register_to_l1glwe_by_trivial_lift(
                    carry_in,
                    &self.aux_data.l1glwe_zero,
                    &self.aux_data.l1glwe_one,
                )?;

                let (graph, output) =
                    add_circuit(a.width(), &c1, &c2, Some(&c_carry), &self.aux_data.enc);

                let parent_op = make_parent_op(&retirement_info);

                self.aux_data
                    .uop_processor
                    .spawn_graph(&graph, &self.aux_data.flow, parent_op);

                *dst = Register::Ciphertext(Ciphertext::L1Glwe {
                    data: output[0..output.len() - 1].to_owned(),
                });

                *carry_out = Register::Ciphertext(Ciphertext::L1Glwe {
                    data: vec![output[output.len() - 1].to_owned()],
                });
            }

            Ok(())
        };

        if let Err(e) = add_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}

/// Add two plaintext numbers together, returning the sum and the carry out.
fn add_with_carry(a: u128, b: u128, carry_in: u128, width: u32) -> (u128, u128) {
    let sum_mask = (0x1 << width) - 1;

    let full_sum = a.wrapping_add(b).wrapping_add(carry_in);

    let sum = full_sum & sum_mask;
    let carry = (full_sum >> width) & 1;

    (sum, carry)
}
