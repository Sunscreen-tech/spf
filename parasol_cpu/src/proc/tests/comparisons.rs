use std::sync::Arc;

use parasol_runtime::Encryption;
use rand::{RngCore, thread_rng};

use crate::{
    ArgsBuilder, FheComputer, Memory,
    proc::IsaOp,
    register_names::*,
    test_utils::{MaybeEncryptedInt, MaybeEncryptedUInt, make_computer_128},
};

use parasol_runtime::test_utils::get_secret_keys_128;

fn run_single_test(
    proc: &mut FheComputer,
    enc: &Encryption,
    comparison: fn(u32, u32) -> bool,
    isa_op: IsaOp,
    encrypted_computation: bool,
    val1: u32,
    val2: u32,
) {
    let sk = get_secret_keys_128();
    let expected = comparison(val1, val2);
    let memory = Arc::new(Memory::new_default_stack());

    let program = memory.allocate_program(&[
        IsaOp::Load(T0, SP, 32, 0),
        IsaOp::Load(T1, SP, 32, 4),
        isa_op,
        IsaOp::Zext(T0, T0, 32),
        IsaOp::Store(A0, T0, 32, 0),
        IsaOp::Ret(),
    ]);

    let args = if matches!(
        isa_op,
        IsaOp::CmpGtS(..) | IsaOp::CmpGeS(..) | IsaOp::CmpLtS(..) | IsaOp::CmpLeS(..)
    ) {
        ArgsBuilder::new()
            .arg(MaybeEncryptedInt::<32>::new(
                val1 as u64,
                enc,
                &sk,
                encrypted_computation,
            ))
            .arg(MaybeEncryptedInt::<32>::new(
                val2 as u64,
                enc,
                &sk,
                encrypted_computation,
            ))
    } else {
        ArgsBuilder::new()
            .arg(MaybeEncryptedUInt::<32>::new(
                val1 as u64,
                enc,
                &sk,
                encrypted_computation,
            ))
            .arg(MaybeEncryptedUInt::<32>::new(
                val2 as u64,
                enc,
                &sk,
                encrypted_computation,
            ))
    };
    let args = args.return_value::<MaybeEncryptedUInt<32>>();

    let ans = proc.run_program(program, &memory, args).unwrap();
    assert_eq!(expected as u32, ans.get(enc, &sk));
}

fn run_comparison_test(
    comparison: fn(u32, u32) -> bool,
    isa_op: IsaOp,
    encrypted_computation: bool,
) {
    let (mut proc, enc) = make_computer_128();

    for _ in 0..=5 {
        let val1 = thread_rng().next_u64() as u32;
        let val2 = thread_rng().next_u64() as u32;
        run_single_test(
            &mut proc,
            &enc,
            comparison,
            isa_op,
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
            isa_op,
            encrypted_computation,
            val1,
            val1,
        );
    }
}

#[test]
fn can_equal_plaintext_inputs() {
    run_comparison_test(|val1, val2| val1 == val2, IsaOp::CmpEq(T0, T0, T1), false);
}

#[test]
fn can_equal_ciphertext_inputs() {
    run_comparison_test(|val1, val2| val1 == val2, IsaOp::CmpEq(T0, T0, T1), true);
}

#[test]
fn can_greater_than_plaintext_inputs() {
    run_comparison_test(|val1, val2| val1 > val2, IsaOp::CmpGt(T0, T0, T1), false);
}

#[test]
fn can_greater_than_ciphertext_inputs() {
    run_comparison_test(|val1, val2| val1 > val2, IsaOp::CmpGt(T0, T0, T1), true);
}

#[test]
fn can_greater_than_or_equal_plaintext_inputs() {
    run_comparison_test(|val1, val2| val1 >= val2, IsaOp::CmpGe(T0, T0, T1), false);
}

#[test]
fn can_greater_than_or_equal_ciphertext_inputs() {
    run_comparison_test(|val1, val2| val1 >= val2, IsaOp::CmpGe(T0, T0, T1), true);
}

#[test]
fn can_less_than_plaintext_inputs() {
    run_comparison_test(|val1, val2| val1 < val2, IsaOp::CmpLt(T0, T0, T1), false);
}

#[test]
fn can_less_than_ciphertext_inputs() {
    run_comparison_test(|val1, val2| val1 < val2, IsaOp::CmpLt(T0, T0, T1), true);
}

#[test]
fn can_less_than_or_equal_plaintext_inputs() {
    run_comparison_test(|val1, val2| val1 <= val2, IsaOp::CmpLe(T0, T0, T1), false);
}

#[test]
fn can_less_than_or_equal_ciphertext_inputs() {
    run_comparison_test(|val1, val2| val1 <= val2, IsaOp::CmpLe(T0, T0, T1), true);
}

#[test]
fn can_greater_than_signed_plaintext_inputs() {
    run_comparison_test(
        |val1, val2| val1 as i32 > val2 as i32,
        IsaOp::CmpGtS(T0, T0, T1),
        false,
    );
}

#[test]
fn can_greater_than_signed_ciphertext_inputs() {
    run_comparison_test(
        |val1, val2| val1 as i32 > val2 as i32,
        IsaOp::CmpGtS(T0, T0, T1),
        true,
    );
}

#[test]
fn can_greater_than_or_equal_signed_plaintext_inputs() {
    run_comparison_test(
        |val1, val2| val1 as i32 >= val2 as i32,
        IsaOp::CmpGeS(T0, T0, T1),
        false,
    );
}

#[test]
fn can_greater_than_or_equal_signed_ciphertext_inputs() {
    run_comparison_test(
        |val1, val2| val1 as i32 >= val2 as i32,
        IsaOp::CmpGeS(T0, T0, T1),
        true,
    );
}

#[test]
fn can_less_than_signed_plaintext_inputs() {
    run_comparison_test(
        |val1, val2| (val1 as i32) < (val2 as i32),
        IsaOp::CmpLtS(T0, T0, T1),
        false,
    );
}

#[test]
fn can_less_than_signed_ciphertext_inputs() {
    run_comparison_test(
        |val1, val2| (val1 as i32) < (val2 as i32),
        IsaOp::CmpLtS(T0, T0, T1),
        true,
    );
}

#[test]
fn can_less_than_or_equal_signed_plaintext_inputs() {
    run_comparison_test(
        |val1, val2| val1 as i32 <= val2 as i32,
        IsaOp::CmpLeS(T0, T0, T1),
        false,
    );
}

#[test]
fn can_less_than_or_equal_signed_ciphertext_inputs() {
    run_comparison_test(
        |val1, val2| val1 as i32 <= val2 as i32,
        IsaOp::CmpLeS(T0, T0, T1),
        true,
    );
}
