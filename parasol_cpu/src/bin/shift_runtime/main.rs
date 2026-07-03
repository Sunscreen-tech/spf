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

    for v_bits in [8, 16] {
        for s_bits in [8] {
            println!("USE {v_bits} {s_bits}");

            for i in 1..=n {
                eprintln!("Round {i} / {n} for {v_bits} value {s_bits} shift");

                let value = rng().next_u64() as u128 & ((1 << v_bits) - 1);
                let shift = rng().next_u64() as u128 & ((1 << s_bits) - 1);

                let memory = Memory::new_default_stack();

                let program = memory.allocate_program(&[
                    Load(T0, SP, v_bits, 0),
                    Load(T1, SP, s_bits, (v_bits / 8).max(s_bits / 8) as i32),
                    Shr(T2, T0, T1),
                    Move(T0, T2),
                    Load(T0, SP, v_bits, 0),
                    Shra(T2, T0, T1),
                    Move(T0, T2),
                    Load(T0, SP, v_bits, 0),
                    Shl(T2, T0, T1),
                    Move(T0, T2),
                    Load(T0, SP, v_bits, 0),
                    Rotl(T2, T0, T1),
                    Move(T0, T2),
                    Load(T0, SP, v_bits, 0),
                    Rotr(T2, T0, T1),
                    Move(T0, T2),
                    Ret(),
                ]);

                let args = ArgsBuilder::new()
                    .arg_dyn(DynamicUInt::encrypt_secret(
                        value,
                        &enc,
                        &sk,
                        v_bits as usize,
                    ))
                    .arg_dyn(DynamicUInt::encrypt_secret(
                        shift,
                        &enc,
                        &sk,
                        s_bits as usize,
                    ))
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
}
