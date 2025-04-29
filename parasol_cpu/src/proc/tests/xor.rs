use rand::{RngCore, thread_rng};

use crate::{
    proc::IsaOp,
    proc::program::FheProgram,
    test_utils::{buffer_from_value_80, make_computer_80, read_result},
    tomasulo::registers::RegisterName,
};

fn can_xor(val1: u32, val2: u32, encrypted_val1: bool, encrypted_val2: bool) {
    let (mut proc, enc) = make_computer_80();

    let encrypted_computation = encrypted_val1 || encrypted_val2;

    let expected = val1 ^ val2;

    let buffer_0 = buffer_from_value_80(val1, &enc, encrypted_val1);
    let buffer_1 = buffer_from_value_80(val2, &enc, encrypted_val2);
    let output_buffer = buffer_from_value_80(0u32, &enc, encrypted_computation);

    let program = FheProgram::from_instructions(vec![
        IsaOp::BindReadOnly(RegisterName::new(0), 0, encrypted_val1),
        IsaOp::BindReadOnly(RegisterName::new(1), 1, encrypted_val2),
        IsaOp::BindReadWrite(RegisterName::new(2), 2, encrypted_computation),
        IsaOp::Load(RegisterName::new(0), RegisterName::new(0), 32),
        IsaOp::Load(RegisterName::new(1), RegisterName::new(1), 32),
        IsaOp::Xor(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        IsaOp::Store(RegisterName::new(2), RegisterName::new(2), 32),
    ]);

    let params = vec![buffer_0, buffer_1, output_buffer];

    proc.run_program(
        &program,
        &params,
        if encrypted_computation { 200_000 } else { 100 },
    )
    .unwrap();

    let ans = read_result::<u32>(&params[2], &enc, encrypted_computation);
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
