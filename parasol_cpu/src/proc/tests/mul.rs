use std::sync::Arc;

use rand::{RngCore, thread_rng};

use crate::{
    ArgsBuilder, Memory,
    proc::IsaOp,
    register_names::*,
    test_utils::{Bits, BitsUnsigned, MaybeEncryptedUInt, make_computer_128},
};

use parasol_runtime::test_utils::get_secret_keys_128;

fn get_mask(width: u32) -> u128 {
    if width < 128 {
        (1 << width) - 1
    } else {
        u128::MAX
    }
}

#[test]
fn can_unsigned_mul_plain_plain() {
    let case = |a: u128, b: u128, width| {
        let (mut proc, _) = make_computer_128();

        let memory = Arc::new(Memory::new_default_stack());
        let a_ptr = memory.try_allocate_type(&a).unwrap();
        let b_ptr = memory.try_allocate_type(&b).unwrap();
        let c_ptr = memory.try_allocate(16).unwrap();

        let program = memory.allocate_program(&vec![
            IsaOp::Load(T0, SP, 32, 0),
            IsaOp::Load(T1, SP, 32, 4),
            IsaOp::Load(T2, SP, 32, 8),
            IsaOp::Load(T0, T0, width, 0),
            IsaOp::Load(T1, T1, width, 0),
            IsaOp::Mul(T0, T0, T1),
            IsaOp::Store(T2, T0, width, 0),
            IsaOp::Ret(),
        ]);

        let args = ArgsBuilder::new()
            .arg(a_ptr)
            .arg(b_ptr)
            .arg(c_ptr)
            .no_return_value();

        proc.run_program(program, &memory, args).unwrap();

        let mask = get_mask(width);

        let expected = a.wrapping_mul(b) & mask;
        let actual: u128 = memory.try_load_type(c_ptr).unwrap();

        assert_eq!(
            expected, actual,
            "{a:#02x} * {b:#02x}, expected: {expected:#02x}, ans_multiply: {actual:#02x}, width {width}",
        );
    };

    for width in [8, 16, 32, 64, 128] {
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
    <BitsUnsigned as Bits<N>>::PlaintextType: Into<u64>,
{
    let case = |a: u64, b: u64, width| {
        let (mut proc, enc) = make_computer_128();
        let sk = get_secret_keys_128();

        let memory = Arc::new(Memory::new_default_stack());

        let program = memory.allocate_program(&[
            IsaOp::Load(T0, SP, N as u32, 0),
            IsaOp::Load(T1, SP, N as u32, (N / 8) as i32),
            IsaOp::Mul(T0, T0, T1),
            IsaOp::Store(RP, T0, N as u32, 0),
            IsaOp::Ret(),
        ]);

        let args = ArgsBuilder::new()
            .arg(MaybeEncryptedUInt::<N>::new(a as u128, &enc, &sk, a_enc))
            .arg(MaybeEncryptedUInt::<N>::new(b as u128, &enc, &sk, b_enc))
            .return_value::<MaybeEncryptedUInt<N>>();

        let actual = proc.run_program(program, &memory, args).unwrap();

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
