use rand::{RngCore, thread_rng};

use crate::{
    proc::IsaOp,
    proc::{Buffer, program::FheProgram},
    test_utils::make_computer_80,
    tomasulo::registers::RegisterName,
};

use parasol_runtime::test_utils::get_secret_keys_80;

#[test]
fn can_or_plaintext_inputs() {
    let (mut proc, _enc) = make_computer_80();

    let val1 = 14u32;
    let val2 = 7u32;
    let expected = val1 | val2;

    let buffer_0 = Buffer::plain_from_value(&val1);
    let buffer_1 = Buffer::plain_from_value(&val2);
    let output_buffer = Buffer::plain_from_value(&0u32);

    let program = FheProgram::from_instructions(vec![
        IsaOp::BindReadOnly(RegisterName::new(0), 0, false),
        IsaOp::BindReadOnly(RegisterName::new(1), 1, false),
        IsaOp::BindReadWrite(RegisterName::new(2), 2, false),
        IsaOp::Load(RegisterName::new(0), RegisterName::new(0), 32),
        IsaOp::Load(RegisterName::new(1), RegisterName::new(1), 32),
        IsaOp::Or(
            RegisterName::new(2),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        IsaOp::Store(RegisterName::new(2), RegisterName::new(2), 32),
    ]);

    let params = vec![buffer_0, buffer_1, output_buffer];

    proc.run_program(&program, &params).unwrap();

    let ans = params[2].plain_try_into_value::<u32>().unwrap();
    assert_eq!(expected, ans);
}

#[test]
fn can_or_ciphertext_inputs() {
    let (mut proc, enc) = make_computer_80();
    let mut test = |val1: u8, val2: u8| {
        let expected = val1 | val2;

        let buffer_0 = Buffer::cipher_from_value(&val1, &enc, &get_secret_keys_80());
        let buffer_1 = Buffer::cipher_from_value(&val2, &enc, &get_secret_keys_80());
        let output_buffer = Buffer::cipher_from_value(&0u8, &enc, &get_secret_keys_80());

        let program = FheProgram::from_instructions(vec![
            IsaOp::BindReadOnly(RegisterName::new(0), 0, true),
            IsaOp::BindReadOnly(RegisterName::new(1), 1, true),
            IsaOp::BindReadWrite(RegisterName::new(2), 2, true),
            IsaOp::Load(RegisterName::new(0), RegisterName::new(0), 4),
            IsaOp::Load(RegisterName::new(1), RegisterName::new(1), 4),
            IsaOp::Or(
                RegisterName::new(2),
                RegisterName::new(0),
                RegisterName::new(1),
            ),
            IsaOp::Store(RegisterName::new(2), RegisterName::new(2), 4),
        ]);

        let params = vec![buffer_0, buffer_1, output_buffer];

        proc.run_program(&program, &params).unwrap();

        let answer = params[2]
            .cipher_try_into_value::<u8>(&enc, &get_secret_keys_80())
            .unwrap();

        assert_eq!(expected, answer);
    };

    for _ in 0..=10 {
        let val1 = (thread_rng().next_u64() % 16) as u8;
        let val2 = (thread_rng().next_u64() % 16) as u8;
        test(val1, val2);
    }
}
