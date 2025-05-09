use std::sync::Arc;

use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{Encryption, Evaluation, fluent::UInt};

use crate::{get_ck, get_sk};

#[test]
fn can_run_from_elf() {
    let memory = Arc::new(Memory::new_from_elf(include_bytes!("../test_data/add")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let args = ArgsBuilder::new()
        .arg(UInt::<8, _>::encrypt_secret(42, &enc, sk))
        .arg(UInt::<8, _>::encrypt_secret(54, &enc, sk))
        .return_value::<UInt<8, _>>();

    let prog = memory.get_function_entry("add").unwrap();

    let result = proc.run_program(prog, &memory, args, 200_000).unwrap();

    assert_eq!(result.1.decrypt(&enc, sk), 96);
}
