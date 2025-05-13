use std::sync::Arc;

use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{Encryption, Evaluation, fluent::UInt};

use crate::{get_ck, get_sk};

#[test]
fn can_run_from_elf() {
    let memory =
        Arc::new(Memory::new_from_elf(include_bytes!("../test_data/zext_and_trunc")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let u32_ptr = memory
        .try_allocate_type(&UInt::<32, _>::encrypt_secret(0, &enc, sk))
        .unwrap();
    let u8_ptr = memory
        .try_allocate_type(&UInt::<8, _>::encrypt_secret(0, &enc, sk))
        .unwrap();
    let bool_ptr = memory
        .try_allocate_type(&UInt::<8, _>::encrypt_secret(0, &enc, sk))
        .unwrap();
    let comparison_output_ptr = memory
        .try_allocate_type(&UInt::<32, _>::encrypt_secret(0, &enc, sk))
        .unwrap();

    let args = ArgsBuilder::new()
        .arg(UInt::<8, _>::encrypt_secret(42, &enc, sk))
        .arg(UInt::<32, _>::encrypt_secret(123456789, &enc, sk))
        .arg(u32_ptr)
        .arg(u8_ptr)
        .arg(bool_ptr)
        .arg(comparison_output_ptr)
        .no_return_value();

    let prog = memory.get_function_entry("zext_and_trunc").unwrap();

    proc.run_program(prog, &memory, args).unwrap();

    let u32_val = memory
        .try_load_type::<UInt<32, _>>(u32_ptr)
        .unwrap()
        .decrypt(&enc, sk);
    let u8_val = memory
        .try_load_type::<UInt<8, _>>(u8_ptr)
        .unwrap()
        .decrypt(&enc, sk);
    let bool_val = memory
        .try_load_type::<UInt<8, _>>(bool_ptr)
        .unwrap()
        .decrypt(&enc, sk);
    let comparison_val = memory
        .try_load_type::<UInt<32, _>>(comparison_output_ptr)
        .unwrap()
        .decrypt(&enc, sk);

    assert_eq!(u32_val, 123456831);
    assert_eq!(u8_val, 63);
    assert_eq!(bool_val, 1);
    assert_eq!(comparison_val, 9);
}
