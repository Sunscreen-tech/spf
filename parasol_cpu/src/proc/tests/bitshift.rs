use parasol_runtime::Encryption;
use rand::{RngCore, thread_rng};

use crate::{
    FheComputer,
    proc::IsaOp,
    proc::program::FheProgram,
    test_utils::{buffer_from_value_80, make_computer_80, read_result},
    tomasulo::registers::RegisterName,
};

#[allow(clippy::too_many_arguments)]
fn run_single_test(
    proc: &mut FheComputer,
    enc: &Encryption,
    operation: fn(u8, u8) -> u8,
    isa_op: IsaOp,
    encrypted_value: bool,
    encrypted_shift: bool,
    value: u8,
    shift: u8,
) {
    let expected = operation(value, shift);

    let output_encrypted = encrypted_value || encrypted_shift;

    let buffer_value = buffer_from_value_80(value, enc, encrypted_value);
    let buffer_shift = buffer_from_value_80(shift, enc, encrypted_shift);
    let output_buffer = buffer_from_value_80(0u8, enc, output_encrypted);

    let program = FheProgram::from_instructions(vec![
        IsaOp::BindReadOnly(RegisterName::new(0), 0, encrypted_value),
        IsaOp::BindReadOnly(RegisterName::new(1), 1, encrypted_shift),
        IsaOp::BindReadWrite(RegisterName::new(2), 2, output_encrypted),
        IsaOp::Load(RegisterName::new(0), RegisterName::new(0), 8),
        IsaOp::Load(RegisterName::new(1), RegisterName::new(1), 8),
        isa_op,
        IsaOp::Store(RegisterName::new(2), RegisterName::new(2), 8),
    ]);

    let params = vec![buffer_value, buffer_shift, output_buffer];

    proc.run_program(&program, &params).unwrap();

    let ans: u8 = read_result(&params[2], enc, output_encrypted);
    assert_eq!(
        expected, ans,
        "value: {:#08b}, shift: {}, expected: {:#08b}, actual: {:#08b}",
        value, shift, expected, ans
    );
}

fn run_shift_test(
    operation: fn(u8, u8) -> u8,
    isa_op: IsaOp,
    encrypted_value: bool,
    encrypted_shift: bool,
) {
    let (mut proc, enc) = make_computer_80();

    let mask = 0b111;

    for _ in 0..=10 {
        let value = thread_rng().next_u32() as u8;
        let shift = (thread_rng().next_u32() & mask) as u8;

        run_single_test(
            &mut proc,
            &enc,
            operation,
            isa_op.clone(),
            encrypted_value,
            encrypted_shift,
            value,
            shift,
        );
    }
}

#[test]
fn can_shift_right_plain_value_plain_shift() {
    run_shift_test(
        |value, shift| value >> shift,
        IsaOp::Shr(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        false,
        false,
    );
}

#[test]
fn can_shift_right_encrypted_value_plain_shift() {
    run_shift_test(
        |value, shift| value >> shift,
        IsaOp::Shr(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        true,
        false,
    );
}

#[test]
fn can_shift_right_plain_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value >> shift,
        IsaOp::Shr(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        false,
        true,
    );
}

#[test]
fn can_shift_right_encrypted_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value >> shift,
        IsaOp::Shr(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        true,
        true,
    );
}
#[test]
fn can_arith_shift_right_plain_value_plain_shift() {
    run_shift_test(
        |value, shift| ((value as i8) >> shift) as u8,
        IsaOp::Shra(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        false,
        false,
    );
}

#[test]
fn can_arith_shift_right_encrypted_value_plain_shift() {
    run_shift_test(
        |value, shift| ((value as i8) >> shift) as u8,
        IsaOp::Shra(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        true,
        false,
    );
}

#[test]
fn can_arith_shift_right_plain_value_encrypted_shift() {
    run_shift_test(
        |value, shift| ((value as i8) >> shift) as u8,
        IsaOp::Shra(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        false,
        true,
    );
}

#[test]
fn can_arith_shift_right_encrypted_value_encrypted_shift() {
    run_shift_test(
        |value, shift| ((value as i8) >> shift) as u8,
        IsaOp::Shra(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        true,
        true,
    );
}

#[test]
fn can_shift_left_plain_value_plain_shift() {
    run_shift_test(
        |value, shift| value << shift,
        IsaOp::Shl(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        false,
        false,
    );
}

#[test]
fn can_shift_left_encrypted_value_plain_shift() {
    run_shift_test(
        |value, shift| value << shift,
        IsaOp::Shl(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        true,
        false,
    );
}

#[test]
fn can_shift_left_plain_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value << shift,
        IsaOp::Shl(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        false,
        true,
    );
}

#[test]
fn can_shift_left_encrypted_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value << shift,
        IsaOp::Shl(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        true,
        true,
    );
}

#[test]
fn can_rotate_right_plain_value_plain_shift() {
    run_shift_test(
        |value, shift| value.rotate_right(shift as u32),
        IsaOp::Rotr(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        false,
        false,
    );
}

#[test]
fn can_rotate_right_encrypted_value_plain_shift() {
    run_shift_test(
        |value, shift| value.rotate_right(shift as u32),
        IsaOp::Rotr(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        true,
        false,
    );
}

#[test]
fn can_rotate_right_plain_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value.rotate_right(shift as u32),
        IsaOp::Rotr(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        false,
        true,
    );
}

#[test]
fn can_rotate_right_encrypted_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value.rotate_right(shift as u32),
        IsaOp::Rotr(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        true,
        true,
    );
}

#[test]
fn can_rotate_left_plain_value_plain_shift() {
    run_shift_test(
        |value, shift| value.rotate_left(shift as u32),
        IsaOp::Rotl(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        false,
        false,
    );
}

#[test]
fn can_rotate_left_encrypted_value_plain_shift() {
    run_shift_test(
        |value, shift| value.rotate_left(shift as u32),
        IsaOp::Rotl(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        true,
        false,
    );
}

#[test]
fn can_rotate_left_plain_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value.rotate_left(shift as u32),
        IsaOp::Rotl(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        false,
        true,
    );
}

#[test]
fn can_rotate_left_encrypted_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value.rotate_left(shift as u32),
        IsaOp::Rotl(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        true,
        true,
    );
}
