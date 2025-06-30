use std::sync::Arc;

use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{
    Encryption, Evaluation,
    fluent::{UInt, UInt32},
};

use crate::{get_ck, get_sk};

#[test]
fn can_run_from_elf() {
    let memory = Arc::new(Memory::new_from_elf(include_bytes!("../test_data/transfer")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let sender = memory
        .try_allocate_type(&UInt32::encrypt_secret(42, &enc, sk))
        .unwrap();
    let receiver = memory
        .try_allocate_type(&UInt32::encrypt_secret(29, &enc, sk))
        .unwrap();

    let args = ArgsBuilder::new()
        .arg(sender)
        .arg(receiver)
        .arg(UInt32::encrypt_secret(26, &enc, sk))
        .no_return_value();

    let prog = memory.get_function_entry("transfer").unwrap();

    proc.run_program(prog, &memory, args).unwrap();

    let new_sender = memory
        .try_load_type::<UInt<32, _>>(sender)
        .unwrap()
        .decrypt(&enc, sk);

    let new_receiver = memory
        .try_load_type::<UInt<32, _>>(receiver)
        .unwrap()
        .decrypt(&enc, sk);

    assert_eq!(new_sender, 16);
    assert_eq!(new_receiver, 55);
}
