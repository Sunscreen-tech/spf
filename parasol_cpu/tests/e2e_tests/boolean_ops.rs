use std::sync::Arc;

use itertools::Itertools;
use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{Encryption, Evaluation, fluent::Bool};

use crate::{get_ck, get_sk};

const BOOLEAN_INPUT_OPTIONS: [(bool, bool); 4] =
    [(false, false), (false, true), (true, false), (true, true)];

/// Creates setup for boolean operation tests
fn setup_test() -> (
    Arc<Memory>,
    FheComputer,
    Encryption,
    parasol_runtime::SecretKey,
) {
    let memory =
        Arc::new(Memory::new_from_elf(include_bytes!("../test_data/boolean_ops")).unwrap());
    let sk = get_sk();
    let ck = get_ck();
    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);
    let proc = FheComputer::new(&enc, &eval);
    (memory, proc, enc, sk.clone())
}

/// Test mixed or fully encrypted operations (result is always encrypted when any arg is encrypted)
fn test_operation(function_name: &str, op: fn(bool, bool) -> bool) {
    let (memory, mut proc, enc, sk) = setup_test();

    let prog = memory.get_function_entry(function_name).unwrap();

    for ((a_val, b_val), (encrypt_a, encrypt_b)) in BOOLEAN_INPUT_OPTIONS
        .iter()
        .cartesian_product(BOOLEAN_INPUT_OPTIONS.iter())
    {
        let args = ArgsBuilder::new();

        let args = if *encrypt_a {
            args.arg(Bool::encrypt_secret(*a_val, &enc, &sk))
        } else {
            args.arg(*a_val)
        };

        let args = if *encrypt_b {
            args.arg(Bool::encrypt_secret(*b_val, &enc, &sk))
        } else {
            args.arg(*b_val)
        };

        let actual = if *encrypt_a || *encrypt_b {
            let args = args.return_value::<Bool>();
            let result = proc.run_program(prog, &memory, args).unwrap();

            result.decrypt(&enc, &sk)
        } else {
            // plaintext result if both inputs are plaintext
            let args = args.return_value::<bool>();

            proc.run_program(prog, &memory, args).unwrap()
        };

        let expected = op(*a_val, *b_val);

        assert_eq!(
            actual, expected,
            "{function_name}: {actual} should be {expected}. Inputs were a={a_val} (enc={encrypt_a}), b={b_val} (enc={encrypt_b})"
        );
    }
}

#[test]
fn boolean_and_all_combinations() {
    test_operation("boolean_and", |a, b| a & b);
}

#[test]
fn boolean_or_all_combinations() {
    test_operation("boolean_or", |a, b| a | b);
}

#[test]
fn boolean_xor_all_combinations() {
    test_operation("boolean_xor", |a, b| a ^ b);
}
