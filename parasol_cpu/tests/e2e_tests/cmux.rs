use std::sync::Arc;

use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{
    Encryption, Evaluation,
    fluent::{UInt, UInt8},
};

use crate::{get_ck, get_sk};

#[test]
fn can_run_from_elf() {
    let memory = Arc::new(Memory::new_from_elf(include_bytes!("../test_data/cmux")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let args = ArgsBuilder::new()
        .arg(UInt8::encrypt_secret(42, &enc, sk))
        .arg(UInt8::encrypt_secret(54, &enc, sk))
        .arg(UInt8::encrypt_secret(11, &enc, sk))
        .return_value::<UInt8>();

    let prog = memory.get_function_entry("cmux").unwrap();

    let result = proc.run_program(prog, &memory, args).unwrap();

    assert_eq!(result.decrypt(&enc, sk), 54);

    let args = ArgsBuilder::new()
        .arg(UInt8::encrypt_secret(10, &enc, sk))
        .arg(UInt8::encrypt_secret(54, &enc, sk))
        .arg(UInt8::encrypt_secret(11, &enc, sk))
        .return_value::<UInt8>();

    let result = proc.run_program(prog, &memory, args).unwrap();

    assert_eq!(result.decrypt(&enc, sk), 11);
}
