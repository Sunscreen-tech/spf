use std::sync::Arc;

use parasol_cpu::{
    ArgsBuilder, Memory, RunProgramOptionsBuilder, assembly::IsaOp::*, make_computer_128,
    register_names::*,
};
use parasol_runtime::{fluent::DynamicUInt, test_utils::get_secret_keys_128};
use rand::{RngCore, rng};

fn main() {
    let (mut proc, enc) = make_computer_128();
    let sk = get_secret_keys_128();

    let n = 320;

    for bits in [8, 16, 32, 64] {
        println!("USE {bits}");

        for i in 1..=n {
            eprintln!("Round {i} / {n} for {bits}");

            let val1 = rng().next_u64() as u128 & ((1 << bits) - 1);
            let val2 = rng().next_u64() as u128 & ((1 << bits) - 1);

            let memory = Memory::new_default_stack();

            let program = memory.allocate_program(&[
                Load(T0, SP, bits, 0),
                Load(T1, SP, bits, bits as i32 / 8),
                Add(T2, T0, T1),
                Move(T3, T2),
                Not(T4, T3),
                Move(T1, T4),
                Neg(T2, T1),
                Move(T1, T2),
                And(T3, T1, T0),
                Move(T1, T3),
                Or(T3, T1, T2),
                Move(T2, T3),
                Sub(T1, T2, T3),
                Move(T2, T1),
                Xor(T3, T0, T1),
                Move(T4, T3),
                Mul(T1, T2, T4),
                Move(T2, T1),
                CmpGt(T3, T2, T4),
                AddC(T5, T4, T1, T2, T3),
                Sext(T4, T4, bits),
                SubB(T2, T1, T4, T5, T3),
                Zext(T3, T3, bits),
                Load(T4, SP, bits, 0),
                Cmux(T5, T1, T4, T3),
                Zext(T1, T1, bits),
                CmpEq(T1, T5, T3),
                Load(T1, SP, bits, 0),
                CmpGe(T2, T1, T3),
                Move(T4, T1),
                Load(T1, SP, bits, bits as i32 / 8),
                Zext(T4, T4, bits),
                CmpLe(T3, T1, T4),
                Move(T1, T3),
                Load(T3, SP, bits, bits as i32 / 8),
                Sext(T1, T1, bits),
                CmpLt(T2, T1, T3),
                Move(T4, T2),
                Sext(T4, T4, bits),
                Load(T3, SP, bits, bits as i32 / 8),
                CmpGtS(T2, T4, T3),
                Move(T3, T2),
                Load(T2, SP, bits, bits as i32 / 8),
                Zext(T3, T3, bits),
                CmpGeS(T1, T2, T3),
                Move(T4, T1),
                Load(T1, SP, bits, bits as i32 / 8),
                Zext(T4, T4, bits),
                CmpLeS(T3, T1, T4),
                Move(T1, T3),
                Load(T3, SP, bits, bits as i32 / 8),
                Sext(T1, T1, bits),
                CmpLtS(T2, T1, T3),
                Ret(),
            ]);

            let args = ArgsBuilder::new()
                .arg_dyn(DynamicUInt::encrypt_secret(val1, &enc, &sk, bits as usize))
                .arg_dyn(DynamicUInt::encrypt_secret(val2, &enc, &sk, bits as usize))
                .no_return_value();

            proc.run_program_with_options(
                program,
                &Arc::new(memory),
                args,
                &RunProgramOptionsBuilder::new()
                    .log_instruction_time(true)
                    .build(),
            )
            .unwrap();
        }
    }
}
