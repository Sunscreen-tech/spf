use std::sync::Arc;

use rand::{RngCore, thread_rng};

use crate::{
    ArgsBuilder, Memory,
    proc::IsaOp,
    register_names::*,
    test_utils::{MaybeEncryptedUInt, make_computer_128},
};

use parasol_runtime::test_utils::get_secret_keys_128;

fn can_xor(val1: u32, val2: u32, encrypted_val1: bool, encrypted_val2: bool) {
    let (mut proc, enc) = make_computer_128();
    let sk = get_secret_keys_128();

    let expected = val1 ^ val2;

    let memory = Arc::new(Memory::new_default_stack());

    let program = memory.allocate_program(&[
        IsaOp::Load(T0, SP, 32, 0),
        IsaOp::Load(T1, SP, 32, 4),
        IsaOp::Xor(T0, T0, T1),
        IsaOp::Store(RP, T0, 32, 0),
        IsaOp::Ret(),
    ]);

    let args = ArgsBuilder::new()
        .arg(MaybeEncryptedUInt::<32>::new(
            val1 as u128,
            &enc,
            &sk,
            encrypted_val1,
        ))
        .arg(MaybeEncryptedUInt::<32>::new(
            val2 as u128,
            &enc,
            &sk,
            encrypted_val2,
        ))
        .return_value::<MaybeEncryptedUInt<32>>();

    let ans = proc.run_program(program, &memory, args).unwrap();
    let ans = ans.get(&enc, &sk);

    assert_eq!(expected, ans);
}

#[test]
fn can_xor_plaintext_inputs() {
    for _ in 0..10 {
        let val1 = thread_rng().next_u32();
        let val2 = thread_rng().next_u32();
        can_xor(val1, val2, false, false);
    }
}

#[test]
fn can_xor_ciphertext_left() {
    for _ in 0..5 {
        let val1 = thread_rng().next_u32();
        let val2 = thread_rng().next_u32();
        can_xor(val1, val2, true, false);
    }
}

#[test]
fn can_xor_ciphertext_right() {
    for _ in 0..5 {
        let val1 = thread_rng().next_u32();
        let val2 = thread_rng().next_u32();
        can_xor(val1, val2, false, true);
    }
}

#[test]
fn can_xor_ciphertext_both() {
    for _ in 0..5 {
        let val1 = thread_rng().next_u32();
        let val2 = thread_rng().next_u32();
        can_xor(val1, val2, true, true);
    }
}
