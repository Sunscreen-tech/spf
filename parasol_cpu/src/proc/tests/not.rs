use rand::{RngCore, thread_rng};

use crate::{
    proc::IsaOp,
    proc::program::FheProgram,
    test_utils::{buffer_from_value_80, make_computer_80, read_result},
    tomasulo::registers::RegisterName,
};

fn can_not(val: u32, encrypted_computation: bool) {
    let (mut proc, enc) = make_computer_80();

    let expected = !val;

    let buffer_0 = buffer_from_value_80(val, &enc, encrypted_computation);
    let output_buffer = buffer_from_value_80(0u32, &enc, encrypted_computation);

    let program = FheProgram::from_instructions(vec![
        IsaOp::BindReadOnly(RegisterName::new(0), 0, encrypted_computation),
        IsaOp::BindReadWrite(RegisterName::new(1), 1, encrypted_computation),
        IsaOp::Load(RegisterName::new(0), RegisterName::new(0), 32),
        IsaOp::Not(RegisterName::new(1), RegisterName::new(0)),
        IsaOp::Store(RegisterName::new(1), RegisterName::new(1), 32),
    ]);

    let params = vec![buffer_0, output_buffer];

    proc.run_program(&program, &params).unwrap();

    let ans = read_result::<u32>(&params[1], &enc, encrypted_computation);
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
