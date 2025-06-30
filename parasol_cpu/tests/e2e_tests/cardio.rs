use std::sync::Arc;

use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{Encryption, Evaluation, fluent::UInt8};

use crate::{get_ck, get_sk};

#[test]
fn can_run_from_elf() {
    let memory = Arc::new(Memory::new_from_elf(include_bytes!("../test_data/cardio")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let man = false;
    let smoking = false;
    let diabetic = true;
    let high_bp = true;

    let flags = [man, smoking, diabetic, high_bp]
        .iter()
        .enumerate()
        .map(|(i, &x)| (x as u8) << i)
        .sum::<u8>();

    let args = ArgsBuilder::new()
        .arg(UInt8::encrypt_secret(flags as u128, &enc, sk))
        .arg(UInt8::encrypt_secret(40, &enc, sk))
        .arg(UInt8::encrypt_secret(50, &enc, sk))
        .arg(UInt8::encrypt_secret(70, &enc, sk))
        .arg(UInt8::encrypt_secret(170, &enc, sk))
        .arg(UInt8::encrypt_secret(1, &enc, sk))
        .arg(UInt8::encrypt_secret(1, &enc, sk))
        .return_value::<UInt8>();

    let prog = memory.get_function_entry("cardio").unwrap();

    let result = proc.run_program(prog, &memory, args).unwrap();

    assert_eq!(result.decrypt(&enc, sk), 3);
}
