use std::sync::Arc;

use rand::{RngCore, thread_rng};

use parasol_runtime::test_utils::get_secret_keys_128;

use crate::{
    ArgsBuilder, Memory,
    proc::IsaOp,
    register_names::*,
    test_utils::{MaybeEncryptedUInt, make_computer_80},
};

fn can_not(val: u32, encrypted_computation: bool) {
    let (mut proc, enc) = make_computer_80();
    let sk = get_secret_keys_128();

    let expected = !val;

    let memory = Arc::new(Memory::new_default_stack());

    let args = ArgsBuilder::new()
        .arg(MaybeEncryptedUInt::<32>::new(
            val as u64,
            &enc,
            &sk,
            encrypted_computation,
        ))
        .return_value::<MaybeEncryptedUInt<32>>();

    let program = memory.allocate_program(&[IsaOp::Not(A0, A0), IsaOp::Ret()]);

    let ans = proc.run_program(program, &memory, args).unwrap();
    let ans = ans.get(&enc, &sk);

    assert_eq!(expected, ans);
}

#[test]
fn can_not_plaintext_inputs() {
    for _ in 0..10 {
        let val = thread_rng().next_u32();
        can_not(val, false);
    }
}

#[test]
fn can_not_ciphertext_inputs() {
    for _ in 0..10 {
        let val = thread_rng().next_u32();
        can_not(val, true);
    }
}
