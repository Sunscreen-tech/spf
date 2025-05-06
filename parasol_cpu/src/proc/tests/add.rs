use std::sync::Arc;

use crate::{
    ArgsBuilder, Memory,
    proc::IsaOp,
    registers::*,
    test_utils::{MaybeEncryptedUInt, make_computer_80},
    tomasulo::registers::RegisterName,
};

use parasol_runtime::test_utils::get_secret_keys_80;

#[test]
fn can_add_inputs() {
    let test = |((val1, enc1), (val2, enc2), expected_sum)| {
        let (mut proc, enc) = make_computer_80();
        let sk = get_secret_keys_80();

        let encrypted_computation = enc1 || enc2;

        let memory = Memory::new_default_stack();

        let program = memory.allocate_program(&[IsaOp::Add(A0, A0, A1), IsaOp::Ret()]);

        let args = ArgsBuilder::new()
            .arg(MaybeEncryptedUInt::<32>::new(val1 as u64, &enc, &sk, enc1))
            .arg(MaybeEncryptedUInt::<32>::new(val2 as u64, &enc, &sk, enc2))
            .return_value::<MaybeEncryptedUInt<32>>();

        let (_, result) = proc
            .run_program(program, &Arc::new(memory), args, 200_000)
            .unwrap();

        let ans_sum = result.get(&enc, &sk);

        assert_eq!(
            expected_sum, ans_sum,
            "val1: {:#02x}, val2: {:#02x}, expected_sum: {:#02x}, ans_sum: {:#02x}, encrypted computation?: {}",
            val1, val2, expected_sum, ans_sum, encrypted_computation
        );
    };

    for test_case in [
        // Unencrypted tests
        ((15, false), (12, false), 27),
        ((0xffff_ffffu32, false), (1u32, false), 0u32),
        (
            (0xffff_ffffu32, false),
            (0xffff_ffffu32, false),
            0xffff_fffeu32,
        ),
        // Encrypted tests
        ((15, true), (12, false), 27),
        ((0xffff_ffffu32, false), (1u32, true), 0u32),
        (
            (0xffff_ffffu32, true),
            (0xffff_ffffu32, true),
            0xffff_fffeu32,
        ),
    ] {
        test(test_case);
    }
}

#[test]
fn can_add_carry_inputs() {
    let test = |(
        (val1, enc1),
        (val2, enc2),
        (input_carry, enc_input_carry),
        expected_sum,
        expected_carry,
    )| {
        let (mut proc, enc) = make_computer_80();
        let sk = &get_secret_keys_80();

        let encrypted_computation = enc1 || enc2 || enc_input_carry;

        let memory = Memory::new_default_stack();

        let prog_ptr = memory.allocate_program(&[
            IsaOp::Trunc(A2, A2, 1),
            IsaOp::AddC(A0, A1, A0, A1, A2),
            IsaOp::Zext(A1, A1, 32),
            IsaOp::Ret(),
        ]);

        let args = ArgsBuilder::new()
            .arg(MaybeEncryptedUInt::<32>::new(val1 as u64, &enc, sk, enc1))
            .arg(MaybeEncryptedUInt::<32>::new(val2 as u64, &enc, sk, enc2))
            .arg(MaybeEncryptedUInt::<8>::new(
                input_carry as u64,
                &enc,
                sk,
                enc_input_carry,
            ))
            .return_value::<[MaybeEncryptedUInt<32>; 2]>();

        let (_, [ans_sum, ans_carry]) = proc
            .run_program(prog_ptr, &Arc::new(memory), args, 200_000)
            .unwrap();

        let ans_sum = ans_sum.get(&enc, sk);
        let ans_carry = ans_carry.get(&enc, sk);

        assert_eq!(
            expected_sum, ans_sum,
            "val1: {:#02x}, val2: {:#02x}, input_carry: {:#02x}, expected_sum: {:#02x}, ans_sum: {:#02x}, encrypted computation?: {}",
            val1, val2, input_carry, expected_sum, ans_sum, encrypted_computation
        );

        assert_eq!(
            expected_carry, ans_carry,
            "val1: {:#02x}, val2: {:#02x}, input_carry: {:#02x}, expected_carry: {:#02x}, ans_carry: {:#02x}, encrypted computation?: {}",
            val1, val2, input_carry, expected_carry, ans_carry, encrypted_computation
        );
    };

    for test_case in [
        // Plaintext computations
        ((15, false), (12, false), (0, false), 27, 0), // Add no carry, no carry out
        ((15, false), (12, false), (1, false), 28, 0), // Add carry, no carry out
        (
            (0xffff_ffffu32, false),
            (1u32, false),
            (0u32, false),
            0u32,
            1u32,
        ), // Add no carry, carry out
        (
            (0xffff_ffffu32, false),
            (1u32, false),
            (1u32, false),
            1u32,
            1u32,
        ), // Add carry, carry out
        (
            (0xffff_ffffu32, false),
            (0xffff_ffffu32, false),
            (0u32, false),
            0xffff_fffeu32,
            1u32,
        ), // Add no carry, carry out
        (
            (0xffff_ffffu32, false),
            (0xffff_ffffu32, false),
            (1u32, false),
            0xffff_ffffu32,
            1u32,
        ), // Add carry, carry out
        // Encrypted computations
        ((15, true), (12, true), (0, true), 27, 0), // Add no carry, no carry out
        ((15, true), (12, false), (1, true), 28, 0), // Add carry, no carry out
        (
            (0xffff_ffffu32, false),
            (1u32, true),
            (0u32, true),
            0u32,
            1u32,
        ), // Add no carry, carry out
        (
            (0xffff_ffffu32, true),
            (1u32, true),
            (1u32, false),
            1u32,
            1u32,
        ), // Add carry, carry out
        (
            (0xffff_ffffu32, true),
            (0xffff_ffffu32, true),
            (0u32, true),
            0xffff_fffeu32,
            1u32,
        ), // Add no carry, carry out
        (
            (0xffff_ffffu32, true),
            (0xffff_ffffu32, true),
            (1u32, true),
            0xffff_ffffu32,
            1u32,
        ), // Add carry, carry out
    ] {
        test(test_case);
    }
}

#[test]
fn add_use_same_dst_and_src() {
    let (mut proc, _enc) = make_computer_80();

    let memory = Memory::new_default_stack();
    let program_ptr = memory.allocate_program(&[IsaOp::Add(A0, A0, A0), IsaOp::Ret()]);

    let args = ArgsBuilder::new().arg(10u16).return_value::<u16>();

    let (_, actual) = proc
        .run_program(program_ptr, &Arc::new(memory), args, 200_000)
        .unwrap();

    assert_eq!(actual, 20);
}
