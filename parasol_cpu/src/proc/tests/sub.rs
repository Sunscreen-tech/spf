use std::sync::Arc;

use crate::{
    ArgsBuilder, Memory,
    proc::IsaOp,
    register_names::*,
    test_utils::{MaybeEncryptedUInt, make_computer_128},
};

use parasol_runtime::test_utils::get_secret_keys_128;

#[test]
fn can_sub_inputs() {
    let test = |((val1, enc1), (val2, enc2), expected_sum)| {
        let (mut proc, enc) = make_computer_128();
        let sk = get_secret_keys_128();

        let encrypted_computation = enc1 || enc2;

        let args = ArgsBuilder::new()
            .arg(MaybeEncryptedUInt::<32>::new(val1 as u128, &enc, &sk, enc1))
            .arg(MaybeEncryptedUInt::<32>::new(val2 as u128, &enc, &sk, enc2))
            .return_value::<MaybeEncryptedUInt<32>>();

        let memory = Arc::new(Memory::new_default_stack());

        let program = memory.allocate_program(&[
            IsaOp::Load(T0, SP, 32, 0),
            IsaOp::Load(T1, SP, 32, 4),
            IsaOp::Sub(T0, T0, T1),
            IsaOp::Store(RP, T0, 32, 0),
            IsaOp::Ret(),
        ]);

        let ans_sum = proc.run_program(program, &memory, args).unwrap();

        let ans_sum = ans_sum.get(&enc, &sk);

        assert_eq!(
            expected_sum, ans_sum,
            "val1: {val1:#02x}, val2: {val2:#02x}, expected_sum: {expected_sum:#02x}, ans_sum: {ans_sum:#02x}, encrypted computation?: {encrypted_computation}"
        );
    };

    for test_case in [
        // Unencrypted tests
        ((15, false), (12, false), 3),
        ((0u32, false), (1u32, false), u32::MAX),
        ((0u32, false), (0xffff_ffffu32, false), 1u32),
        // Encrypted tests
        ((15, true), (12, false), 3),
        ((0u32, false), (1u32, true), u32::MAX),
        ((0u32, true), (0xffff_ffffu32, true), 1u32),
    ] {
        test(test_case);
    }
}

#[test]
fn can_sub_borrow_inputs() {
    let test = |(
        (val1, enc1),
        (val2, enc2),
        (input_borrow, enc_input_borrow),
        expected_sum,
        expected_borrow,
    )| {
        let (mut proc, enc) = make_computer_128();
        let sk = get_secret_keys_128();

        let encrypted_computation = enc1 || enc2 || enc_input_borrow;

        let memory = Arc::new(Memory::new_default_stack());

        let program = memory.allocate_program(&[
            IsaOp::Load(T0, SP, 32, 0),
            IsaOp::Load(T1, SP, 32, 4),
            IsaOp::Load(T2, SP, 32, 8),
            IsaOp::Trunc(T2, T2, 1),
            IsaOp::SubB(T0, T1, T0, T1, T2),
            IsaOp::Zext(T1, T1, 8),
            IsaOp::Store(RP, T0, 32, 0),
            IsaOp::Store(RP, T1, 8, 4),
            IsaOp::Ret(),
        ]);

        let args = ArgsBuilder::new()
            .arg(MaybeEncryptedUInt::<32>::new(val1 as u128, &enc, &sk, enc1))
            .arg(MaybeEncryptedUInt::<32>::new(val2 as u128, &enc, &sk, enc1))
            .arg(MaybeEncryptedUInt::<32>::new(
                input_borrow as u128,
                &enc,
                &sk,
                enc_input_borrow,
            ))
            .return_value::<[MaybeEncryptedUInt<8>; 5]>();

        // Diff || borrow is 5 bytes: 4 for the difference and 1 for the borrow
        let result = proc.run_program(program, &memory, args).unwrap();

        let ans_diff = u32::from_le_bytes(
            result
                .iter()
                .take(4)
                .map(|x| x.get(&enc, &sk))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );

        let ans_borrow = result[4].get(&enc, &sk) as u32;

        assert_eq!(
            expected_sum, ans_diff,
            "val1: {val1:#02x}, val2: {val2:#02x}, input_borrow: {input_borrow:#02x}, expected_sum: {expected_sum:#02x}, ans_sum: {ans_diff:#02x}, encrypted computation?: {encrypted_computation}"
        );

        assert_eq!(
            expected_borrow, ans_borrow,
            "val1: {val1:#02x}, val2: {val2:#02x}, input_borrow: {input_borrow:#02x}, expected_borrow: {expected_borrow:#02x}, ans_borrow: {ans_borrow:#02x}, encrypted computation?: {encrypted_computation}"
        );
    };

    for test_case in [
        // Plaintext computations
        ((15, false), (12, false), (0, false), 3, 0), // sub no borrow, no borrow out
        ((15, false), (12, false), (1, false), 2, 0), // sub borrow, no borrow out
        ((0u32, false), (1u32, false), (0u32, false), u32::MAX, 1u32), // sub no borrow, borrow out
        (
            (0u32, false),
            (1u32, false),
            (1u32, false),
            u32::MAX - 1,
            1u32,
        ), // sub borrow, borrow out
        (
            (0u32, false),
            (0xffff_ffffu32, false),
            (0u32, false),
            1u32,
            1u32,
        ), // sub no borrow, borrow out
        (
            (0u32, false),
            (0xffff_ffffu32, false),
            (1u32, false),
            0u32,
            1u32,
        ), // sub borrow, borrow out
        // Encrypted computations
        ((15, true), (12, false), (0, false), 3, 0), // sub no borrow, no borrow out
        ((15, false), (12, true), (1, false), 2, 0), // sub borrow, no borrow out
        ((0u32, false), (1u32, false), (0u32, true), u32::MAX, 1u32), // sub no borrow, borrow out
        (
            (0u32, true),
            (1u32, true),
            (1u32, false),
            u32::MAX - 1,
            1u32,
        ), // sub borrow, borrow out
        (
            (0u32, true),
            (0xffff_ffffu32, false),
            (0u32, true),
            1u32,
            1u32,
        ), // sub no borrow, borrow out
        (
            (0u32, false),
            (0xffff_ffffu32, true),
            (1u32, true),
            0u32,
            1u32,
        ), // sub borrow, borrow out
        (
            (0u32, true),
            (0xffff_ffffu32, true),
            (1u32, true),
            0u32,
            1u32,
        ), // sub borrow, borrow out
    ] {
        test(test_case);
    }
}

#[test]
fn sub_use_same_dst_and_src() {
    let (mut proc, _enc) = make_computer_128();

    let memory = Arc::new(Memory::new_default_stack());

    let args = ArgsBuilder::new().arg(10u32).return_value::<u32>();

    let ans = proc
        .run_program(
            memory.allocate_program(&[IsaOp::Sub(RP, RP, RP), IsaOp::Ret()]),
            &memory,
            args,
        )
        .unwrap();

    assert_eq!(ans, 0);
}
