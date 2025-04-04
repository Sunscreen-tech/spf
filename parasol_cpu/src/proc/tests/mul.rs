use rand::{thread_rng, RngCore};

use crate::{
    proc::program::FheProgram, proc::IsaOp, test_utils::make_computer_80,
    tomasulo::registers::RegisterName, Buffer,
};

use parasol_runtime::test_utils::get_secret_keys_80;

#[test]
fn can_unsigned_mul_plain_plain() {
    let case = |a: u128, b: u128, width| {
        let (mut proc, _) = make_computer_80();

        let a_buf = Buffer::plain_from_value(&a);
        let b_buf = Buffer::plain_from_value(&b);

        let c_buf = Buffer::plain_from_value(&0u128);

        let program = FheProgram::from_instructions(vec![
            IsaOp::BindReadOnly(RegisterName::named(0), 0, false),
            IsaOp::BindReadOnly(RegisterName::named(1), 1, false),
            IsaOp::BindReadWrite(RegisterName::named(2), 2, false),
            IsaOp::Load(RegisterName::named(0), RegisterName::named(0), width),
            IsaOp::Load(RegisterName::named(1), RegisterName::named(1), width),
            IsaOp::Mul(
                RegisterName::named(2),
                RegisterName::named(0),
                RegisterName::named(1),
            ),
            IsaOp::Store(RegisterName::named(2), RegisterName::named(2), width),
        ]);

        let params = vec![a_buf, b_buf, c_buf];

        proc.run_program(&program, &params).unwrap();

        let mask = (0x1u128 << width) - 1;

        let expected = a.wrapping_mul(b) & mask;
        let actual = params[2].plain_try_into_value::<u128>().unwrap();

        assert_eq!(
            expected, actual,
            "{a:#02x} * {b:#02x}, expected: {expected:#02x}, ans_multiply: {actual:#02x}",
        );
    };

    for width in [7, 8, 32, 64, 128] {
        for _ in 0..10 {
            let mask = (0x1u128 << width) - 1;

            let a = thread_rng().next_u64() as u128 & mask;
            let b = thread_rng().next_u64() as u128 & mask;

            case(a, b, width);
        }
    }
}

#[test]
fn can_unsigned_mul_cipher_cipher() {
    let case = |a: u128, b: u128, width| {
        let sk = get_secret_keys_80();
        let (mut proc, enc) = make_computer_80();

        let a_buf = Buffer::cipher_from_value(&a, &enc, &sk);
        let b_buf = Buffer::cipher_from_value(&b, &enc, &sk);

        let c_buf = Buffer::cipher_from_value(&0u128, &enc, &sk);

        let program = FheProgram::from_instructions(vec![
            IsaOp::BindReadOnly(RegisterName::named(0), 0, true),
            IsaOp::BindReadOnly(RegisterName::named(1), 1, true),
            IsaOp::BindReadWrite(RegisterName::named(2), 2, true),
            IsaOp::Load(RegisterName::named(0), RegisterName::named(0), width),
            IsaOp::Load(RegisterName::named(1), RegisterName::named(1), width),
            IsaOp::Mul(
                RegisterName::named(2),
                RegisterName::named(0),
                RegisterName::named(1),
            ),
            IsaOp::Store(RegisterName::named(2), RegisterName::named(2), width),
        ]);

        let params = vec![a_buf, b_buf, c_buf];

        proc.run_program(&program, &params).unwrap();

        let mask = (0x1u128 << width) - 1;

        let expected = a.wrapping_mul(b) & mask;
        let actual = params[2].cipher_try_into_value::<u128>(&enc, &sk).unwrap();

        assert_eq!(
            expected, actual,
            "{a:#02x} * {b:#02x}, expected: {expected:#02x}, ans_multiply: {actual:#02x}",
        );
    };

    for width in [7, 16, 32] {
        for _ in 0..2 {
            let mask = (0x1u128 << width) - 1;

            let a = thread_rng().next_u64() as u128 & mask;
            let b = thread_rng().next_u64() as u128 & mask;

            case(a, b, width);
        }
    }
}

#[test]
fn can_multiply_cipher_plain() {
    let case = |a: u128, b: u128, width| {
        let sk = get_secret_keys_80();
        let (mut proc, enc) = make_computer_80();

        let a_buf = Buffer::cipher_from_value(&a, &enc, &sk);
        let b_buf = Buffer::plain_from_value(&b);

        let c_buf = Buffer::cipher_from_value(&0u128, &enc, &sk);

        let program = FheProgram::from_instructions(vec![
            IsaOp::BindReadOnly(RegisterName::named(0), 0, true),
            IsaOp::BindReadOnly(RegisterName::named(1), 1, false),
            IsaOp::BindReadWrite(RegisterName::named(2), 2, true),
            IsaOp::Load(RegisterName::named(0), RegisterName::named(0), width),
            IsaOp::Load(RegisterName::named(1), RegisterName::named(1), width),
            IsaOp::Mul(
                RegisterName::named(2),
                RegisterName::named(0),
                RegisterName::named(1),
            ),
            IsaOp::Store(RegisterName::named(2), RegisterName::named(2), width),
        ]);

        let params = vec![a_buf, b_buf, c_buf];

        proc.run_program(&program, &params).unwrap();

        let mask = (0x1u128 << width) - 1;

        let expected = a.wrapping_mul(b) & mask;
        let actual = params[2].cipher_try_into_value::<u128>(&enc, &sk).unwrap();

        assert_eq!(
            expected, actual,
            "{a:#02x} * {b:#02x}, expected: {expected:#02x}, ans_sum: {actual:#02x}",
        );
    };

    for width in [7, 16, 32] {
        for _ in 0..2 {
            let mask = (0x1u128 << width) - 1;

            let a = thread_rng().next_u64() as u128 & mask;
            let b = thread_rng().next_u64() as u128 & mask;

            case(a, b, width);
        }
    }
}
