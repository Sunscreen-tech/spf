use std::sync::Arc;

use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{Encryption, Evaluation, fluent::UInt8};

use crate::{get_ck, get_sk};

#[test]
fn can_run_from_elf() {
    let memory =
        Arc::new(Memory::new_from_elf(include_bytes!("../test_data/hamming_distance")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let a = 0xFEEDF00D_CAFEBABEu64
        .to_le_bytes()
        .map(|x| UInt8::encrypt_secret(x as u128, &enc, sk));
    let b = 0x12345678_9ABCDEF0u64
        .to_le_bytes()
        .map(|x| UInt8::encrypt_secret(x as u128, &enc, sk));

    let a = memory.try_allocate_type(&a).unwrap();
    let b = memory.try_allocate_type(&b).unwrap();

    let args = ArgsBuilder::new()
        .arg(a)
        .arg(b)
        .arg(8)
        .return_value::<UInt8>();

    let prog = memory.get_function_entry("hamming_distance").unwrap();

    let result = proc.run_program(prog, &memory, args).unwrap();

    assert_eq!(result.decrypt(&enc, sk), 30);
}
