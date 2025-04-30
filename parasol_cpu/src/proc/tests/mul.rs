use std::sync::Arc;

use rand::{RngCore, thread_rng};

use crate::{
    ArgsBuilder, Memory,
    proc::IsaOp,
    test_utils::{Bits, BitsUnsigned, MaybeEncryptedUInt, make_computer_80, make_computer_128},
    tomasulo::registers::RegisterName,
};

use parasol_runtime::test_utils::get_secret_keys_128;

fn get_mask(width: u32) -> u128 {
    if width < 16 {
        (0x1u128 << (8 * width)) - 1
    } else {
        u128::MAX
    }
}

#[test]
fn can_unsigned_mul_plain_plain() {
    let case = |a: u128, b: u128, width| {
        let (mut proc, _) = make_computer_80();

        let memory = Arc::new(Memory::new_default_stack());
        let a_ptr = memory.try_allocate_type(&a).unwrap();
        let b_ptr = memory.try_allocate_type(&b).unwrap();
        let c_ptr = memory.try_allocate(16).unwrap();

        let program = memory.allocate_program(&vec![
            IsaOp::Load(RegisterName::new(0), RegisterName::new(10), width),
            IsaOp::Load(RegisterName::new(1), RegisterName::new(11), width),
            IsaOp::Mul(
                RegisterName::new(0),
                RegisterName::new(0),
                RegisterName::new(1),
            ),
            IsaOp::Store(RegisterName::new(12), RegisterName::new(0), width),
            IsaOp::Ret(),
        ]);

        let args = ArgsBuilder::new()
            .arg(a_ptr)
            .arg(b_ptr)
            .arg(c_ptr)
            .no_return_value();

        proc.run_program(program, &memory, args, 100).unwrap();

        let mask = get_mask(width);

        let expected = a.wrapping_mul(b) & mask;
        let actual: u128 = memory.try_load_type(c_ptr).unwrap();

        assert_eq!(
            expected, actual,
            "{a:#02x} * {b:#02x}, expected: {expected:#02x}, ans_multiply: {actual:#02x}, width {width}",
        );
    };

    for width in [1, 2, 4, 8, 16] {
        for _ in 0..10 {
            let mask = get_mask(width);

            let a = thread_rng().next_u64() as u128 & mask;
            let b = thread_rng().next_u64() as u128 & mask;

            case(a, b, width);
        }
    }
}

fn enc_case<const N: usize>(a_enc: bool, b_enc: bool)
where
    BitsUnsigned: Bits<N>,
{
    let case = |a: u64, b: u64, width| {
        let (mut proc, enc) = make_computer_128();
        let sk = get_secret_keys_128();

        let memory = Arc::new(Memory::new_default_stack());

        let program = memory.allocate_program(&[
            IsaOp::Mul(
                RegisterName::new(10),
                RegisterName::new(11),
                RegisterName::new(10),
            ),
            IsaOp::Ret(),
        ]);

        let args = ArgsBuilder::new()
            .arg(MaybeEncryptedUInt::<N>::new(a, &enc, &sk, a_enc))
            .arg(MaybeEncryptedUInt::<N>::new(b, &enc, &sk, b_enc))
            .return_value::<MaybeEncryptedUInt<N>>();

        let actual = proc.run_program(program, &memory, args, 500_000).unwrap();

        let expected = a.wrapping_mul(b) & ((0x1 << N) - 1);
        let actual: u64 = actual.get(&enc, &sk).into();

        assert_eq!(
            expected, actual,
            "{a:#02x} * {b:#02x}, expected: {expected:#02x}, ans_multiply: {actual:#02x}, width {width}",
        );
    };

    for _ in 0..10 {
        let mask = (0x1 << N) - 1;

        let a = thread_rng().next_u64() & mask;
        let b = thread_rng().next_u64() & mask;

        case(a, b, N as u32);
    }
}

#[test]
fn can_unsigned_mul_cipher_cipher() {
    enc_case::<16>(true, true);
    enc_case::<32>(true, true);
}

#[test]
fn can_unsigned_multiply_cipher_plain() {
    enc_case::<16>(true, false);
    enc_case::<32>(true, false);
}
