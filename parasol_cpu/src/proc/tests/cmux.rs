use std::sync::Arc;

use rand::{RngCore, thread_rng};

use crate::{
    ArgsBuilder, Memory,
    proc::IsaOp,
    register_names::*,
    test_utils::{MaybeEncryptedUInt, make_computer_128},
};

use parasol_runtime::test_utils::get_secret_keys_128;

fn cmux_test_program() -> Vec<IsaOp> {
    vec![
        IsaOp::Load(T0, SP, 32, 0),
        IsaOp::Load(T1, SP, 32, 4),
        IsaOp::Load(T2, SP, 32, 8),
        IsaOp::LoadI(T3, 10, 32),
        IsaOp::CmpGt(T3, T0, T3),
        IsaOp::Cmux(T0, T3, T1, T2),
        IsaOp::Store(RP, T0, 32, 0),
        IsaOp::Ret(),
    ]
}

fn can_cmux(encrypted_computation: bool) {
    let (mut proc, enc) = make_computer_128();
    let sk = get_secret_keys_128();

    // Make an array of size 10 of random numbers modulo 20
    let random_conditions = (0..10).map(|_| thread_rng().next_u32() % 20);

    for bound in random_conditions {
        let a = thread_rng().next_u32();
        let b = thread_rng().next_u32();

        let expected = if bound > 10 { a } else { b };

        let memory = Arc::new(Memory::new_default_stack());

        let args = ArgsBuilder::new()
            .arg(MaybeEncryptedUInt::<32>::new(
                bound as u64,
                &enc,
                &sk,
                encrypted_computation,
            ))
            .arg(MaybeEncryptedUInt::<32>::new(
                a as u64,
                &enc,
                &sk,
                encrypted_computation,
            ))
            .arg(MaybeEncryptedUInt::<32>::new(
                b as u64,
                &enc,
                &sk,
                encrypted_computation,
            ))
            .return_value::<MaybeEncryptedUInt<32>>();

        let program = memory.allocate_program(&cmux_test_program());

        let ans = proc.run_program(program, &memory, args).unwrap();

        assert_eq!(expected, ans.get(&enc, &sk));
    }
}

#[test]
fn can_cmux_plaintext() {
    can_cmux(false);
}

#[test]
fn can_cmux_ciphertext() {
    can_cmux(true);
}
