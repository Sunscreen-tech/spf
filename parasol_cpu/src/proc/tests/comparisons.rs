use std::sync::Arc;

use parasol_runtime::Encryption;
use rand::{RngCore, thread_rng};

use crate::{
    ArgsBuilder, FheComputer, Memory,
    proc::IsaOp,
    test_utils::{MaybeEncryptedUInt, make_computer_80},
    tomasulo::registers::RegisterName,
};

use parasol_runtime::test_utils::get_secret_keys_80;

fn run_single_test(
    proc: &mut FheComputer,
    enc: &Encryption,
    comparison: fn(u32, u32) -> bool,
    isa_op: IsaOp,
    encrypted_computation: bool,
    val1: u32,
    val2: u32,
) {
    let sk = get_secret_keys_80();
    let expected = comparison(val1, val2);
    let memory = Arc::new(Memory::new_default_stack());

    let program = memory.allocate_program(&[
        isa_op,
        IsaOp::Zext(RegisterName::new(10), RegisterName::new(10), 32),
        IsaOp::Ret(),
    ]);

    let args = ArgsBuilder::new()
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
        .return_value::<MaybeEncryptedUInt<32>>();

    let (_, ans) = proc.run_program(program, &memory, args, 200_000).unwrap();
    assert_eq!(expected as u32, ans.get(enc, &sk));
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
    run_comparison_test(
        |val1, val2| val1 == val2,
        IsaOp::CmpEq(
            RegisterName::new(10),
            RegisterName::new(10),
            RegisterName::new(11),
        ),
        false,
    );
}

#[test]
fn can_equal_ciphertext_inputs() {
    run_comparison_test(
        |val1, val2| val1 == val2,
        IsaOp::CmpEq(
            RegisterName::new(10),
            RegisterName::new(10),
            RegisterName::new(11),
        ),
        true,
    );
}

#[test]
fn can_greater_than_plaintext_inputs() {
    run_comparison_test(
        |val1, val2| val1 > val2,
        IsaOp::CmpGt(
            RegisterName::new(10),
            RegisterName::new(10),
            RegisterName::new(11),
        ),
        false,
    );
}

#[test]
fn can_greater_than_ciphertext_inputs() {
    run_comparison_test(
        |val1, val2| val1 > val2,
        IsaOp::CmpGt(
            RegisterName::new(10),
            RegisterName::new(10),
            RegisterName::new(11),
        ),
        true,
    );
}

#[test]
fn can_greater_than_or_equal_plaintext_inputs() {
    run_comparison_test(
        |val1, val2| val1 >= val2,
        IsaOp::CmpGe(
            RegisterName::new(10),
            RegisterName::new(10),
            RegisterName::new(11),
        ),
        false,
    );
}

#[test]
fn can_greater_than_or_equal_ciphertext_inputs() {
    run_comparison_test(
        |val1, val2| val1 >= val2,
        IsaOp::CmpGe(
            RegisterName::new(10),
            RegisterName::new(10),
            RegisterName::new(11),
        ),
        true,
    );
}

#[test]
fn can_less_than_plaintext_inputs() {
    run_comparison_test(
        |val1, val2| val1 < val2,
        IsaOp::CmpLt(
            RegisterName::new(10),
            RegisterName::new(10),
            RegisterName::new(11),
        ),
        false,
    );
}

#[test]
fn can_less_than_ciphertext_inputs() {
    run_comparison_test(
        |val1, val2| val1 < val2,
        IsaOp::CmpLt(
            RegisterName::new(10),
            RegisterName::new(10),
            RegisterName::new(11),
        ),
        true,
    );
}

#[test]
fn can_less_than_or_equal_plaintext_inputs() {
    run_comparison_test(
        |val1, val2| val1 <= val2,
        IsaOp::CmpLe(
            RegisterName::new(10),
            RegisterName::new(10),
            RegisterName::new(11),
        ),
        false,
    );
}

#[test]
fn can_less_than_or_equal_ciphertext_inputs() {
    run_comparison_test(
        |val1, val2| val1 <= val2,
        IsaOp::CmpLe(
            RegisterName::new(10),
            RegisterName::new(10),
            RegisterName::new(11),
        ),
        true,
    );
}
