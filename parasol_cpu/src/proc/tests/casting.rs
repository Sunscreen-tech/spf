use itertools::Itertools;
use rand::{RngCore, thread_rng};

use crate::test_utils::read_result;
use crate::{
    proc::IsaOp,
    proc::program::FheProgram,
    test_utils::{buffer_from_value_80, make_computer_80},
    tomasulo::registers::RegisterName,
};

fn casting(zero_extend: bool, encrypted_computation: bool) {
    let supported_sizes = [1, 8, 16, 32];

    let combinations = supported_sizes
        .iter()
        .cartesian_product(supported_sizes.iter())
        .map(|(input_width, output_width)| {
            (
                (*input_width, *output_width),
                if zero_extend {
                    input_width <= output_width
                } else {
                    input_width >= output_width
                },
            )
        });

    for ((input_width, output_width), valid) in combinations {
        // TODO: If a program fails then currently this will stall the test when
        // a valid program is passed in. We should enable resetting the
        // processor on failure. In the meantime, we can just create a new
        // processor for each loop.
        let (mut proc, enc) = make_computer_80();
        let enc = &enc;

        // Get a random 32 bit value
        let value = thread_rng().next_u32();
        let shift_width = if zero_extend {
            input_width
        } else {
            output_width
        };
        let mask = (((1u64) << shift_width) - 1) as u32;
        let expected = value & mask;

        let buffer_0 = buffer_from_value_80(value, enc, encrypted_computation);
        let output_buffer = buffer_from_value_80(0u32, enc, encrypted_computation);

        let program = FheProgram::from_instructions(vec![
            IsaOp::BindReadOnly(RegisterName::new(0), 0, encrypted_computation),
            IsaOp::BindReadWrite(RegisterName::new(1), 1, encrypted_computation),
            IsaOp::Load(RegisterName::new(0), RegisterName::new(0), input_width),
            if zero_extend {
                IsaOp::Zext(RegisterName::new(1), RegisterName::new(0), output_width)
            } else {
                IsaOp::Trunc(RegisterName::new(1), RegisterName::new(0), output_width)
            },
            IsaOp::Store(RegisterName::new(1), RegisterName::new(1), output_width),
        ]);

        let params = vec![buffer_0, output_buffer];

        let result = proc.run_program(&program, &params, 100);

        match (valid, result) {
            (true, Ok(_)) => {
                let ans: u32 = read_result(&params[1], enc, encrypted_computation);
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
            (false, Ok(_)) => panic!("Expected error"),
        }
    }
}

#[test]
fn can_cast_zero_extend_plaintext() {
    for _ in 0..5 {
        casting(true, false);
    }
}

#[test]
fn can_cast_zero_extend_ciphertext() {
    for _ in 0..3 {
        casting(true, true);
    }
}

#[test]
fn can_cast_truncate_plaintext() {
    for _ in 0..5 {
        casting(false, false);
    }
}

#[test]
fn can_cast_truncate_ciphertext() {
    for _ in 3..5 {
        casting(false, true);
    }
}
