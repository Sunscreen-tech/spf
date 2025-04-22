use parasol_runtime::Encryption;
use rand::{RngCore, thread_rng};

use crate::{
    FheComputer,
    proc::IsaOp,
    proc::program::FheProgram,
    test_utils::{buffer_from_value_80, make_computer_80, read_result},
    tomasulo::registers::RegisterName,
};

fn run_single_test(
    proc: &mut FheComputer,
    enc: &Encryption,
    comparison: fn(u32, u32) -> bool,
    isa_op: IsaOp,
    encrypted_computation: bool,
    val1: u32,
    val2: u32,
) {
    let expected = comparison(val1, val2);

    let buffer_0 = buffer_from_value_80(val1, enc, encrypted_computation);
    let buffer_1 = buffer_from_value_80(val2, enc, encrypted_computation);
    let output_buffer = buffer_from_value_80(0u32, enc, encrypted_computation);

    let params = vec![buffer_0, buffer_1, output_buffer];

    let program = FheProgram::from_instructions(vec![
        IsaOp::BindReadOnly(RegisterName::new(0), 0, encrypted_computation),
        IsaOp::BindReadOnly(RegisterName::new(1), 1, encrypted_computation),
        IsaOp::BindReadWrite(RegisterName::new(2), 2, encrypted_computation),
        IsaOp::Load(RegisterName::new(0), RegisterName::new(0), 32),
        IsaOp::Load(RegisterName::new(1), RegisterName::new(1), 32),
        isa_op,
        IsaOp::Store(RegisterName::new(2), RegisterName::new(2), 1),
    ]);

    proc.run_program(&program, &params).unwrap();

    let ans: u32 = read_result(&params[2], enc, encrypted_computation);
    assert_eq!(expected as u32, ans);
}

fn run_comparison_test(
    comparison: fn(u32, u32) -> bool,
    isa_op: IsaOp,
    encrypted_computation: bool,
) {
    let (mut proc, enc) = make_computer_80();

    for _ in 0..=5 {
        let val1 = thread_rng().next_u64() as u32;
        let val2 = thread_rng().next_u64() as u32;
        run_single_test(
            &mut proc,
            &enc,
            comparison,
            isa_op.clone(),
            encrypted_computation,
            val1,
            val2,
        );
    }

    for _ in 0..=5 {
        let val1 = (thread_rng().next_u64() % 16) as u32;

        run_single_test(
            &mut proc,
            &enc,
            comparison,
            isa_op.clone(),
            encrypted_computation,
            val1,
            val1,
        );
    }
}

#[test]
fn can_equal_plaintext_inputs() {
    run_comparison_test(
        |val1, val2| val1 == val2,
        IsaOp::CmpEq(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        false,
    );
}

#[test]
fn can_equal_ciphertext_inputs() {
    run_comparison_test(
        |val1, val2| val1 == val2,
        IsaOp::CmpEq(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        true,
    );
}

#[test]
fn can_greater_than_plaintext_inputs() {
    run_comparison_test(
        |val1, val2| val1 > val2,
        IsaOp::CmpGt(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        false,
    );
}

#[test]
fn can_greater_than_ciphertext_inputs() {
    run_comparison_test(
        |val1, val2| val1 > val2,
        IsaOp::CmpGt(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        true,
    );
}

#[test]
fn can_greater_than_or_equal_plaintext_inputs() {
    run_comparison_test(
        |val1, val2| val1 >= val2,
        IsaOp::CmpGe(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        false,
    );
}

#[test]
fn can_greater_than_or_equal_ciphertext_inputs() {
    run_comparison_test(
        |val1, val2| val1 >= val2,
        IsaOp::CmpGe(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        true,
    );
}

#[test]
fn can_less_than_plaintext_inputs() {
    run_comparison_test(
        |val1, val2| val1 < val2,
        IsaOp::CmpLt(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        false,
    );
}

#[test]
fn can_less_than_ciphertext_inputs() {
    run_comparison_test(
        |val1, val2| val1 < val2,
        IsaOp::CmpLt(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        true,
    );
}

#[test]
fn can_less_than_or_equal_plaintext_inputs() {
    run_comparison_test(
        |val1, val2| val1 <= val2,
        IsaOp::CmpLe(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        false,
    );
}

#[test]
fn can_less_than_or_equal_ciphertext_inputs() {
    run_comparison_test(
        |val1, val2| val1 <= val2,
        IsaOp::CmpLe(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        true,
    );
}
