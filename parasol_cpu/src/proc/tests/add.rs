use crate::{
    proc::IsaOp,
    proc::{Buffer, program::FheProgram},
    test_utils::make_computer_80,
    tomasulo::registers::RegisterName,
};

use parasol_runtime::test_utils::get_secret_keys_80;

#[test]
fn can_add_inputs() {
    let test = |((val1, enc1), (val2, enc2), expected_sum)| {
        let (mut proc, enc) = make_computer_80();

        let encrypted_computation = enc1 || enc2;

        let buffer_0 = if enc1 {
            Buffer::cipher_from_value(&val1, &enc, &get_secret_keys_80())
        } else {
            Buffer::plain_from_value(&val1)
        };
        let buffer_1 = if enc2 {
            Buffer::cipher_from_value(&val2, &enc, &get_secret_keys_80())
        } else {
            Buffer::plain_from_value(&val2)
        };

        let output_buffer0 = if encrypted_computation {
            Buffer::cipher_from_value(&0u32, &enc, &get_secret_keys_80())
        } else {
            Buffer::plain_from_value(&0u32)
        };

        let program = FheProgram::from_instructions(vec![
            IsaOp::BindReadOnly(RegisterName::new(0), 0, enc1),
            IsaOp::BindReadOnly(RegisterName::new(1), 1, enc2),
            IsaOp::BindReadWrite(RegisterName::new(2), 2, encrypted_computation),
            IsaOp::Load(RegisterName::new(0), RegisterName::new(0), 32),
            IsaOp::Load(RegisterName::new(1), RegisterName::new(1), 32),
            IsaOp::Add(
                RegisterName::new(2),
                RegisterName::new(0),
                RegisterName::new(1),
            ),
            IsaOp::Store(RegisterName::new(2), RegisterName::new(2), 32),
        ]);

        let params = vec![buffer_0, buffer_1, output_buffer0];

        proc.run_program(&program, &params).unwrap();

        let ans_sum = if encrypted_computation {
            params[2]
                .cipher_try_into_value::<u32>(&enc, &get_secret_keys_80())
                .unwrap()
        } else {
            params[2].plain_try_into_value::<u32>().unwrap()
        };

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

        let encrypted_computation = enc1 || enc2 || enc_input_carry;

        let buffer_0 = if enc1 {
            Buffer::cipher_from_value(&val1, &enc, &get_secret_keys_80())
        } else {
            Buffer::plain_from_value(&val1)
        };
        let buffer_1 = if enc2 {
            Buffer::cipher_from_value(&val2, &enc, &get_secret_keys_80())
        } else {
            Buffer::plain_from_value(&val2)
        };

        let buffer_2 = if enc_input_carry {
            Buffer::cipher_from_value(&input_carry, &enc, &get_secret_keys_80())
        } else {
            Buffer::plain_from_value(&input_carry)
        };

        let output_buffer0 = if encrypted_computation {
            Buffer::cipher_from_value(&0u32, &enc, &get_secret_keys_80())
        } else {
            Buffer::plain_from_value(&0u32)
        };
        let output_buffer1 = if encrypted_computation {
            Buffer::cipher_from_value(&0u32, &enc, &get_secret_keys_80())
        } else {
            Buffer::plain_from_value(&0u32)
        };

        let program = FheProgram::from_instructions(vec![
            IsaOp::BindReadOnly(RegisterName::new(0), 0, enc1),
            IsaOp::BindReadOnly(RegisterName::new(1), 1, enc2),
            IsaOp::BindReadOnly(RegisterName::new(2), 2, enc_input_carry),
            IsaOp::BindReadWrite(RegisterName::new(3), 3, encrypted_computation),
            IsaOp::BindReadWrite(RegisterName::new(4), 4, encrypted_computation),
            IsaOp::Load(RegisterName::new(0), RegisterName::new(0), 32),
            IsaOp::Load(RegisterName::new(1), RegisterName::new(1), 32),
            IsaOp::Load(RegisterName::new(2), RegisterName::new(2), 1),
            IsaOp::AddC(
                RegisterName::new(3),
                RegisterName::new(4),
                RegisterName::new(0),
                RegisterName::new(1),
                RegisterName::new(2),
            ),
            IsaOp::Store(RegisterName::new(3), RegisterName::new(3), 32),
            IsaOp::Store(RegisterName::new(4), RegisterName::new(4), 1),
        ]);

        let params = vec![buffer_0, buffer_1, buffer_2, output_buffer0, output_buffer1];

        proc.run_program(&program, &params).unwrap();

        let ans_sum = if encrypted_computation {
            params[3]
                .cipher_try_into_value::<u32>(&enc, &get_secret_keys_80())
                .unwrap()
        } else {
            params[3].plain_try_into_value::<u32>().unwrap()
        };
        let ans_carry = if encrypted_computation {
            params[4]
                .cipher_try_into_value::<u32>(&enc, &get_secret_keys_80())
                .unwrap()
        } else {
            params[4].plain_try_into_value::<u32>().unwrap()
        };

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

    let output = Buffer::plain_from_value(&0u32);

    let params = vec![output];

    proc.run_program(
        &FheProgram::from_instructions(vec![
            IsaOp::BindReadWrite(RegisterName::new(0), 0, false),
            IsaOp::LoadI(RegisterName::new(0), 10, 16),
            IsaOp::Add(
                RegisterName::new(0),
                RegisterName::new(0),
                RegisterName::new(0),
            ),
            IsaOp::Store(RegisterName::new(0), RegisterName::new(0), 16),
        ]),
        &params,
    )
    .unwrap();

    let actual = params[0].plain_try_into_value::<u32>().unwrap();

    assert_eq!(actual, 20);
}
