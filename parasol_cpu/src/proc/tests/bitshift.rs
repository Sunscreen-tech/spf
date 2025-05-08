use std::sync::Arc;

use parasol_runtime::{Encryption, test_utils::get_secret_keys_80};
use rand::{RngCore, thread_rng};

use crate::{
    ArgsBuilder, FheComputer, Memory,
    proc::IsaOp,
    register_names::*,
    test_utils::{MaybeEncryptedUInt, make_computer_80},
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
    let sk = get_secret_keys_80();
    let expected = operation(value, shift);

    let memory = Memory::new_default_stack();

    let program = memory.allocate_program(&[
        IsaOp::Trunc(A0, A0, 8),
        IsaOp::Trunc(A1, A1, 8),
        isa_op,
        IsaOp::Ret(),
    ]);

    let args = ArgsBuilder::new()
        .arg(MaybeEncryptedUInt::<8>::new(
            value as u64,
            enc,
            &sk,
            encrypted_value,
        ))
        .arg(MaybeEncryptedUInt::<8>::new(
            shift as u64,
            enc,
            &sk,
            encrypted_shift,
        ))
        .return_value::<MaybeEncryptedUInt<8>>();

    let ans = proc.run_program(program, &Arc::new(memory), args).unwrap();
    let ans = ans.get(enc, &sk);

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
            isa_op,
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
        IsaOp::Shr(A0, A0, A1),
        false,
        false,
    );
}

#[test]
fn can_shift_right_encrypted_value_plain_shift() {
    run_shift_test(
        |value, shift| value >> shift,
        IsaOp::Shr(A0, A0, A1),
        true,
        false,
    );
}

#[test]
fn can_shift_right_plain_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value >> shift,
        IsaOp::Shr(A0, A0, A1),
        false,
        true,
    );
}

#[test]
fn can_shift_right_encrypted_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value >> shift,
        IsaOp::Shr(A0, A0, A1),
        true,
        true,
    );
}
#[test]
fn can_arith_shift_right_plain_value_plain_shift() {
    run_shift_test(
        |value, shift| ((value as i8) >> shift) as u8,
        IsaOp::Shra(A0, A0, A1),
        false,
        false,
    );
}

#[test]
fn can_arith_shift_right_encrypted_value_plain_shift() {
    run_shift_test(
        |value, shift| ((value as i8) >> shift) as u8,
        IsaOp::Shra(A0, A0, A1),
        true,
        false,
    );
}

#[test]
fn can_arith_shift_right_plain_value_encrypted_shift() {
    run_shift_test(
        |value, shift| ((value as i8) >> shift) as u8,
        IsaOp::Shra(A0, A0, A1),
        false,
        true,
    );
}

#[test]
fn can_arith_shift_right_encrypted_value_encrypted_shift() {
    run_shift_test(
        |value, shift| ((value as i8) >> shift) as u8,
        IsaOp::Shra(A0, A0, A1),
        true,
        true,
    );
}

#[test]
fn can_shift_left_plain_value_plain_shift() {
    run_shift_test(
        |value, shift| value << shift,
        IsaOp::Shl(A0, A0, A1),
        false,
        false,
    );
}

#[test]
fn can_shift_left_encrypted_value_plain_shift() {
    run_shift_test(
        |value, shift| value << shift,
        IsaOp::Shl(A0, A0, A1),
        true,
        false,
    );
}

#[test]
fn can_shift_left_plain_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value << shift,
        IsaOp::Shl(A0, A0, A1),
        false,
        true,
    );
}

#[test]
fn can_shift_left_encrypted_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value << shift,
        IsaOp::Shl(A0, A0, A1),
        true,
        true,
    );
}

#[test]
fn can_rotate_right_plain_value_plain_shift() {
    run_shift_test(
        |value, shift| value.rotate_right(shift as u32),
        IsaOp::Rotr(A0, A0, A1),
        false,
        false,
    );
}

#[test]
fn can_rotate_right_encrypted_value_plain_shift() {
    run_shift_test(
        |value, shift| value.rotate_right(shift as u32),
        IsaOp::Rotr(A0, A0, A1),
        true,
        false,
    );
}

#[test]
fn can_rotate_right_plain_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value.rotate_right(shift as u32),
        IsaOp::Rotr(A0, A0, A1),
        false,
        true,
    );
}

#[test]
fn can_rotate_right_encrypted_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value.rotate_right(shift as u32),
        IsaOp::Rotr(A0, A0, A1),
        true,
        true,
    );
}

#[test]
fn can_rotate_left_plain_value_plain_shift() {
    run_shift_test(
        |value, shift| value.rotate_left(shift as u32),
        IsaOp::Rotl(A0, A0, A1),
        false,
        false,
    );
}

#[test]
fn can_rotate_left_encrypted_value_plain_shift() {
    run_shift_test(
        |value, shift| value.rotate_left(shift as u32),
        IsaOp::Rotl(A0, A0, A1),
        true,
        false,
    );
}

#[test]
fn can_rotate_left_plain_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value.rotate_left(shift as u32),
        IsaOp::Rotl(A0, A0, A1),
        false,
        true,
    );
}

#[test]
fn can_rotate_left_encrypted_value_encrypted_shift() {
    run_shift_test(
        |value, shift| value.rotate_left(shift as u32),
        IsaOp::Rotl(A0, A0, A1),
        true,
        true,
    );
}
