use std::sync::Arc;

use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{Encryption, Evaluation, fluent::UInt};

use crate::{get_ck, get_sk};

#[test]
fn can_run_from_elf() {
    let memory = Arc::new(Memory::new_from_elf(include_bytes!("../test_data/payment")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let balance = memory
        .try_allocate_type(&UInt::<32, _>::encrypt_secret(42, &enc, sk))
        .unwrap();

    let args = ArgsBuilder::new()
        .arg(UInt::<32, _>::encrypt_secret(26, &enc, sk))
        .arg(balance)
        .no_return_value();

    let prog = memory.get_function_entry("payment").unwrap();

    proc.run_program(prog, &memory, args).unwrap();

    let new_balance = memory
        .try_load_type::<UInt<32, _>>(balance)
        .unwrap()
        .decrypt(&enc, sk);

    assert_eq!(new_balance, 16);
}
