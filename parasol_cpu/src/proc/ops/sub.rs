use mux_circuits::util::arbitrary_width_borrowing_sub;
use parasol_runtime::circuits::sub_circuit;

use crate::{
    Ciphertext, Error, Register, Result, check_register_width,
    proc::{DispatchIsaOp, fhe_processor::FheProcessor, ops::make_parent_op},
    register_to_l1glwe_by_trivial_lift,
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

impl FheProcessor {
    /// Execute a load instruction.
    pub fn sub(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: u32,
    ) {
        let mut sub_impl = || -> Result<()> {
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
                    val: val1.wrapping_sub(*val2) & mask,
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

                let (graph, output) = sub_circuit(a.width(), &c1, &c2, None, &self.aux_data.enc);

                let parent_op = make_parent_op(&retirement_info);

                self.aux_data
                    .uop_processor
                    .spawn_graph(&graph, &self.aux_data.flow, parent_op);

                // There is a borrow out bit that we will ignore
                *dst = Register::Ciphertext(Ciphertext::L1Glwe {
                    data: output[0..output.len() - 1].to_owned(),
                });
            }

            Ok(())
        };

        if let Err(e) = sub_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sub_borrow(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        borrow_out: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        borrow_in: RobEntryRef<Register>,
        instruction_id: usize,
        pc: u32,
    ) {
        let mut sub_impl = || -> Result<()> {
            unwrap_registers!((mut dst) (mut borrow_out) (a) (b) (borrow_in));

            check_register_width(a, b, instruction_id, pc)?;

            // Check if the borrow bit is a single bit
            if borrow_in.width() != 1 {
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
                    val: borrow_in,
                    width: _,
                },
            ) = (a, b, borrow_in)
            {
                let (sum, borrow) = arbitrary_width_borrowing_sub(*val1, *val2, *borrow_in, *width);

                *dst = Register::Plaintext {
                    val: sum,
                    width: *width,
                };

                *borrow_out = Register::Plaintext {
                    val: borrow,
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
                let c_borrow = register_to_l1glwe_by_trivial_lift(
                    borrow_in,
                    &self.aux_data.l1glwe_zero,
                    &self.aux_data.l1glwe_one,
                )?;

                let (graph, output) =
                    sub_circuit(a.width(), &c1, &c2, Some(&c_borrow), &self.aux_data.enc);

                let parent_op = make_parent_op(&retirement_info);

                self.aux_data
                    .uop_processor
                    .spawn_graph(&graph, &self.aux_data.flow, parent_op);

                *dst = Register::Ciphertext(Ciphertext::L1Glwe {
                    data: output[0..output.len() - 1].to_owned(),
                });

                *borrow_out = Register::Ciphertext(Ciphertext::L1Glwe {
                    data: vec![output[output.len() - 1].to_owned()],
                });
            }

            Ok(())
        };

        if let Err(e) = sub_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }
}
