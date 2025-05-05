use std::sync::Arc;

use itertools::Itertools;
use rand::{RngCore, thread_rng};

use crate::{
    ArgsBuilder, Byte, Memory, ToArg,
    proc::IsaOp,
    test_utils::{Bits, BitsUnsigned, MaybeEncryptedUInt, make_computer_80},
    tomasulo::registers::RegisterName,
};

use parasol_runtime::{Encryption, SecretKey, test_utils::get_secret_keys_80};

enum CastType {
    ZeroExtension,
    SignExtension,
    Truncation,
}

fn casting(cast_type: CastType, encrypted_computation: bool) {
    let supported_sizes = [8u32, 16, 32];

    let combinations = supported_sizes
        .iter()
        .cartesian_product(supported_sizes.iter())
        .map(|(input_width, output_width)| {
            (
                (*input_width, *output_width),
                match cast_type {
                    CastType::SignExtension | CastType::ZeroExtension => {
                        input_width <= output_width
                    }
                    CastType::Truncation => input_width >= output_width,
                },
            )
        });

    for ((input_width, output_width), valid) in combinations {
        // TODO: If a program fails then currently this will stall the test when
        // a valid program is passed in. We should enable resetting the
        // processor on failure. In the meantime, we can just create a new
        // processor for each loop.
        let (mut proc, enc) = make_computer_80();
        let sk = get_secret_keys_80();
        let enc = &enc;

        // Get a random 32 bit value
        let value = thread_rng().next_u32();
        let expected = match cast_type {
            CastType::SignExtension => {
                let mut sign_bit = value & (1 << (input_width - 1));
                let mut extended = value & (((1u64 << input_width) - 1) as u32);
                for _ in 0..output_width.saturating_sub(input_width) {
                    sign_bit <<= 1;
                    extended |= sign_bit;
                }
                extended
            }
            CastType::ZeroExtension => value & (((1u64 << input_width) - 1) as u32),
            CastType::Truncation => value & (((1u64 << output_width) - 1) as u32),
        };

        let memory = Arc::new(Memory::new_default_stack());

        let program = memory.allocate_program(&[
            // Loads use byte widths.
            IsaOp::Load(
                RegisterName::new(10),
                RegisterName::new(10),
                input_width / 8,
            ),
            match cast_type {
                CastType::SignExtension => {
                    IsaOp::Sext(RegisterName::new(10), RegisterName::new(10), output_width)
                }
                CastType::ZeroExtension => {
                    IsaOp::Zext(RegisterName::new(10), RegisterName::new(10), output_width)
                }
                CastType::Truncation => {
                    IsaOp::Trunc(RegisterName::new(10), RegisterName::new(10), output_width)
                }
            },
            // Stores use byte widths.
            IsaOp::Store(
                RegisterName::new(11),
                RegisterName::new(10),
                output_width / 8,
            ),
            IsaOp::Ret(),
        ]);

        // Use the largest case to store our initial value.
        let input = MaybeEncryptedUInt::<32>::new(value as u64, enc, &sk, encrypted_computation);

        let input_ptr = memory.try_allocate(64).unwrap();
        let output_ptr = memory.try_allocate(64).unwrap();

        for (i, b) in input.to_bytes().into_iter().enumerate() {
            memory
                .try_store(input_ptr.try_offset(i as u32).unwrap(), b)
                .unwrap();
        }

        let args = ArgsBuilder::new()
            .arg(input_ptr)
            .arg(output_ptr)
            .no_return_value();

        let result = proc.run_program(program, &memory, args, 200_000);

        match (valid, result) {
            (true, Ok((_, ()))) => {
                let ans_bytes = (0..output_width / 8)
                    .map(|x| memory.try_load(output_ptr.try_offset(x).unwrap()).unwrap())
                    .collect::<Vec<_>>();

                fn get_ans<const N: usize>(
                    ans_bytes: Vec<Byte>,
                    enc: &Encryption,
                    sk: &SecretKey,
                ) -> u32
                where
                    BitsUnsigned: Bits<N>,
                    <BitsUnsigned as Bits<N>>::PlaintextType: Into<u64>,
                {
                    let ans = MaybeEncryptedUInt::<N>::try_from_bytes(ans_bytes).unwrap();
                    let ans: u64 = ans.get(enc, sk).into();
                    ans as u32
                }

                let ans = match output_width {
                    8 => get_ans::<8>(ans_bytes, enc, &sk),
                    16 => get_ans::<16>(ans_bytes, enc, &sk),
                    32 => get_ans::<32>(ans_bytes, enc, &sk),
                    _ => unreachable!(),
                };

                assert_eq!(
                    expected, ans,
                    "input_width: {}, output_width: {}",
                    input_width, output_width
                );
            }
            (false, Err(_)) => {
                // Expected error
                continue;
            }
            (true, Err(e)) => panic!("Unexpected error: {:?}", e),
            (false, Ok((_, ()))) => panic!("Expected error"),
        }
    }
}

#[test]
fn can_cast_zero_extend_plaintext() {
    for _ in 0..5 {
        casting(CastType::ZeroExtension, false);
    }
}

#[test]
fn can_cast_zero_extend_ciphertext() {
    for _ in 0..3 {
        casting(CastType::ZeroExtension, true);
    }
}

#[test]
fn can_cast_sign_extend_plaintext() {
    for _ in 0..5 {
        casting(CastType::SignExtension, false);
    }
}

#[test]
fn can_cast_sign_extend_ciphertext() {
    for _ in 0..3 {
        casting(CastType::SignExtension, true);
    }
}

#[test]
fn can_cast_truncate_plaintext() {
    for _ in 0..5 {
        casting(CastType::Truncation, false);
    }
}

#[test]
fn can_cast_truncate_ciphertext() {
    for _ in 3..5 {
        casting(CastType::Truncation, true);
    }
}
