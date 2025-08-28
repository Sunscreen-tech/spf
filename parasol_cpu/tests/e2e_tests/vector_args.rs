use std::sync::Arc;

use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{Encryption, Evaluation, fluent::UInt8};
use rand::Rng;

use crate::{get_ck, get_sk};

#[test]
fn can_pass_vec_as_dynamic_arg() {
    let memory = Arc::new(Memory::new_from_elf(include_bytes!("../test_data/vector_add")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    // Create vector arguments with random values less than 4
    let mut rng = rand::rng();
    let values_a: [u128; 8] = std::array::from_fn(|_| rng.random_range(0..4));
    let values_b: [u128; 8] = std::array::from_fn(|_| rng.random_range(0..4));
    let data_a: Vec<UInt8> = values_a
        .iter()
        .map(|&i| UInt8::encrypt_secret(i, &enc, sk))
        .collect();
    let data_b: Vec<UInt8> = values_b
        .iter()
        .map(|&i| UInt8::encrypt_secret(i, &enc, sk))
        .collect();

    // Allocate memory for vectors as if they were arrays
    let a = memory.try_allocate_type_dyn(&data_a).unwrap();
    let b = memory.try_allocate_type_dyn(&data_b).unwrap();

    // Allocate output array
    let output_data = std::array::from_fn::<_, 8, _>(|_| UInt8::encrypt_secret(0, &enc, sk));
    let c = memory.try_allocate_type(&output_data).unwrap();

    // Use arg_dyn for vectors instead of arg for arrays
    let args = ArgsBuilder::new()
        .arg(a) // pointer arguments
        .arg(b)
        .arg(c)
        .no_return_value();

    let prog = memory.get_function_entry("vector_add").unwrap();

    proc.run_program(prog, &memory, args).unwrap();

    let result = memory
        .try_load_type::<[UInt8; 8]>(c)
        .unwrap()
        .map(|r| r.decrypt(&enc, sk) as u8);

    // Expected result is element-wise addition of values_a and values_b
    let expected: [u8; 8] = [
        (values_a[0] + values_b[0]) as u8,
        (values_a[1] + values_b[1]) as u8,
        (values_a[2] + values_b[2]) as u8,
        (values_a[3] + values_b[3]) as u8,
        (values_a[4] + values_b[4]) as u8,
        (values_a[5] + values_b[5]) as u8,
        (values_a[6] + values_b[6]) as u8,
        (values_a[7] + values_b[7]) as u8,
    ];
    assert_eq!(result, expected);
}

#[test]
fn empty_vec_handling() {
    // Test that empty vectors work correctly
    let empty_u32: Vec<u32> = vec![];
    let empty_u8: Vec<u8> = vec![];

    let args = ArgsBuilder::new()
        .arg_dyn(empty_u32)
        .arg_dyn(empty_u8)
        .no_return_value();

    // Should not panic and should create valid call data
    let _size = args.alloc_size(); // Just verify it doesn't panic
}
