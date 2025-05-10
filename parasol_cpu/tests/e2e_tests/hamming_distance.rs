use std::sync::Arc;

use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{Encryption, Evaluation, fluent::UInt};

use crate::{get_ck, get_sk};

#[test]
fn can_run_from_elf() {
    env_logger::init();

    let memory =
        Arc::new(Memory::new_from_elf(include_bytes!("../test_data/hamming_distance")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let args = ArgsBuilder::new()
        .arg(UInt::<64, _>::encrypt_secret(
            0xFEEDF00D_CAFEBABEu64,
            &enc,
            sk,
        ))
        .arg(UInt::<64, _>::encrypt_secret(
            0x12345678_9ABCDEF0u64,
            &enc,
            sk,
        ))
        .return_value::<UInt<8, _>>();

    let prog = memory.get_function_entry("hamming_distance").unwrap();

    let result = proc.run_program(prog, &memory, args).unwrap();

    assert_eq!(result.decrypt(&enc, sk), 30);
}
