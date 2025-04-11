use std::sync::Arc;

use parasol_concurrency::AtomicRefCell;
use parasol_runtime::{
    CiphertextType, FheCircuit, FheEdge, FheOp, L1GlweCiphertext,
    circuits::mul::append_uint_multiply, prune,
};

use crate::{
    Ciphertext, FheProcessor, Register, Result, check_register_width,
    proc::DispatchIsaOp,
    proc::ops::{insert_ciphertext_inputs, make_parent_op},
    tomasulo::{registers::RobEntryRef, tomasulo_processor::RetirementInfo},
    unwrap_registers,
};

use super::trivially_encrypt_value_l1glwe;

impl FheProcessor {
    pub fn unsigned_multiply(
        &mut self,
        retirement_info: RetirementInfo<DispatchIsaOp>,
        dst: RobEntryRef<Register>,
        a: RobEntryRef<Register>,
        b: RobEntryRef<Register>,
        instruction_id: usize,
        pc: usize,
    ) {
        let mut mul_impl = || -> Result<()> {
            let constant_pool = self.constant_pool.clone();
            unwrap_registers!([constant_pool] (mut dst) (a) (b));
            check_register_width(a, b, instruction_id, pc)?;

            let mask = (0x1u128 << a.width()) - 1;

            let width = a.width();

            match (a, b) {
                (
                    Register::Plaintext { val: a, width },
                    Register::Plaintext { val: b, width: _ },
                ) => {
                    *dst = Register::Plaintext {
                        val: a.wrapping_mul(*b) & mask,
                        width: *width,
                    };

                    FheProcessor::retire(&retirement_info, Ok(()));
                }
                (Register::Ciphertext(a), Register::Ciphertext(b)) => {
                    self.unsigned_multiply_cipher_cipher(&retirement_info, dst, a, b, width as u32);
                }
                (Register::Ciphertext(a), Register::Plaintext { val: b, width }) => {
                    self.multiply_cipher_plain(&retirement_info, dst, a, *b, *width);
                }
                (Register::Plaintext { val: a, width }, Register::Ciphertext(b)) => {
                    self.multiply_cipher_plain(&retirement_info, dst, b, *a, *width);
                }
            };

            Ok(())
        };

        if let Err(e) = mul_impl() {
            FheProcessor::retire(&retirement_info, Err(e));
        }
    }

    fn unsigned_multiply_cipher_cipher(
        &mut self,
        retirement_info: &RetirementInfo<DispatchIsaOp>,
        dst: &mut Register,
        a: &Ciphertext,
        b: &Ciphertext,
        width: u32,
    ) {
        let mut graph = FheCircuit::new();

        let a = insert_ciphertext_inputs(&mut graph, a, CiphertextType::L1GgswCiphertext);
        let b = insert_ciphertext_inputs(&mut graph, b, CiphertextType::L1GgswCiphertext);

        assert_eq!(a.len(), b.len());

        let (lo, _hi) = append_uint_multiply::<L1GlweCiphertext>(&mut graph, &a, &b);

        let dst_data = (0..width)
            .map(|_| Arc::new(AtomicRefCell::new(self.aux_data.enc.allocate_glwe_l1())))
            .collect::<Vec<_>>();

        assert_eq!(lo.len(), dst_data.len());

        let mut outputs = vec![];

        lo.iter().zip(dst_data.iter()).for_each(|(lo, dst)| {
            let output = graph.add_node(FheOp::OutputGlwe1(dst.clone()));
            graph.add_edge(*lo, output, FheEdge::Unary);
            outputs.push(output);
        });

        // Prune the hi word of the multiplication, as we only use it in
        // mul_wide
        let graph = prune(&graph, &outputs).into();

        let parent_op = make_parent_op(retirement_info);

        *dst = Register::Ciphertext(Ciphertext::L1Glwe { data: dst_data });

        self.aux_data
            .uop_processor
            .spawn_graph(&graph, &self.aux_data.flow, parent_op);
    }

    fn multiply_cipher_plain(
        &mut self,
        retirement_info: &RetirementInfo<DispatchIsaOp>,
        dst: &mut Register,
        a: &Ciphertext,
        b: u128,
        width: u32,
    ) {
        let b = trivially_encrypt_value_l1glwe(
            b,
            width,
            &self.aux_data.l1glwe_zero,
            &self.aux_data.l1glwe_one,
        );

        let b = Ciphertext::L1Glwe { data: b };

        self.unsigned_multiply_cipher_cipher(retirement_info, dst, a, &b, width);
    }
}
