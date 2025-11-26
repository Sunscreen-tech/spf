//! Tests for 64-bit constant handling in Parasol CPU.
//!
//! Verifies that the Parasol ISA correctly loads and operates on 64-bit
//! immediate constants, which may require special handling in instruction
//! encoding due to their size.

use std::sync::Arc;

use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{Encryption, Evaluation, fluent::Int64};

use crate::{get_ck, get_sk};

const CONST_64: i64 = 0x123456789ABCDEF0u64 as i64;
const CONST_HIGH_BITS_64: i64 = 0xFF00000000000000u64 as i64;
const CONST_A: i64 = 0xAAAABBBBCCCCDDDDu64 as i64;
const CONST_B: i64 = 0x1111222233334444u64 as i64;
const CONST_MAX: i64 = i64::MAX; // 0x7FFFFFFFFFFFFFFF
const CONST_MIN: i64 = i64::MIN; // 0x8000000000000000
const CONST_NEG_ONE: i64 = -1i64; // 0xFFFFFFFFFFFFFFFF

#[test]
fn test_add_const_64_enc() {
    let memory =
        Arc::new(Memory::new_from_elf(include_bytes!("../test_data/large_constants")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let args = ArgsBuilder::new()
        .arg(Int64::encrypt_secret(100, &enc, sk))
        .return_value::<Int64>();

    let prog = memory.get_function_entry("add_const_64_enc").unwrap();
    let result = proc.run_program(prog, &memory, args).unwrap();

    let expected = 100i64.wrapping_add(CONST_64);
    assert_eq!(result.decrypt(&enc, sk), expected as i128);
}

#[test]
fn test_add_const_64_plain() {
    let memory =
        Arc::new(Memory::new_from_elf(include_bytes!("../test_data/large_constants")).unwrap());

    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let args = ArgsBuilder::new().arg(100i64).return_value::<i64>();

    let prog = memory.get_function_entry("add_const_64_plain").unwrap();
    let result = proc.run_program(prog, &memory, args).unwrap();

    let expected = 100i64.wrapping_add(CONST_64);
    assert_eq!(result, expected);
}

#[test]
fn test_add_high_bits_64() {
    let memory =
        Arc::new(Memory::new_from_elf(include_bytes!("../test_data/large_constants")).unwrap());

    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let args = ArgsBuilder::new().arg(42i64).return_value::<i64>();

    let prog = memory.get_function_entry("add_high_bits_64").unwrap();
    let result = proc.run_program(prog, &memory, args).unwrap();

    let expected = 42i64.wrapping_add(CONST_HIGH_BITS_64);
    assert_eq!(result, expected);
}

#[test]
fn test_sum_array_64() {
    let memory =
        Arc::new(Memory::new_from_elf(include_bytes!("../test_data/large_constants")).unwrap());

    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    // 4-element array - allocate in memory and pass pointer
    let arr: [i64; 4] = [10, 20, 30, 40];
    let arr_ptr = memory.try_allocate_type(&arr).unwrap();

    let args = ArgsBuilder::new()
        .arg(arr_ptr)
        .arg(4i32)
        .return_value::<i64>();

    let prog = memory.get_function_entry("sum_array_64").unwrap();
    let result = proc.run_program(prog, &memory, args).unwrap();

    assert_eq!(result, 100i64);
}

#[test]
fn test_add_two_consts_64() {
    let memory =
        Arc::new(Memory::new_from_elf(include_bytes!("../test_data/large_constants")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let args = ArgsBuilder::new()
        .arg(Int64::encrypt_secret(5, &enc, sk))
        .return_value::<Int64>();

    let prog = memory.get_function_entry("add_two_consts_64").unwrap();
    let result = proc.run_program(prog, &memory, args).unwrap();

    let expected = 5i64.wrapping_add(CONST_A).wrapping_add(CONST_B);
    assert_eq!(result.decrypt(&enc, sk), expected as i128);
}

#[test]
fn test_add_max_const() {
    let memory =
        Arc::new(Memory::new_from_elf(include_bytes!("../test_data/large_constants")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let args = ArgsBuilder::new()
        .arg(Int64::encrypt_secret(10, &enc, sk))
        .return_value::<Int64>();

    let prog = memory.get_function_entry("add_max_const").unwrap();
    let result = proc.run_program(prog, &memory, args).unwrap();

    let expected = 10i64.wrapping_add(CONST_MAX);
    assert_eq!(result.decrypt(&enc, sk), expected as i128);
}

#[test]
fn test_add_min_const() {
    let memory =
        Arc::new(Memory::new_from_elf(include_bytes!("../test_data/large_constants")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let args = ArgsBuilder::new()
        .arg(Int64::encrypt_secret(10, &enc, sk))
        .return_value::<Int64>();

    let prog = memory.get_function_entry("add_min_const").unwrap();
    let result = proc.run_program(prog, &memory, args).unwrap();

    let expected = 10i64.wrapping_add(CONST_MIN);
    assert_eq!(result.decrypt(&enc, sk), expected as i128);
}

#[test]
fn test_add_negative_one() {
    let memory =
        Arc::new(Memory::new_from_elf(include_bytes!("../test_data/large_constants")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let args = ArgsBuilder::new()
        .arg(Int64::encrypt_secret(100, &enc, sk))
        .return_value::<Int64>();

    let prog = memory.get_function_entry("add_negative_one").unwrap();
    let result = proc.run_program(prog, &memory, args).unwrap();

    let expected = 100i64.wrapping_add(CONST_NEG_ONE);
    assert_eq!(result.decrypt(&enc, sk), expected as i128);
}
