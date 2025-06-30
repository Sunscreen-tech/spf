use std::sync::Arc;

use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{
    Encryption, Evaluation,
    fluent::{UInt, UInt16},
};

use crate::{get_ck, get_sk};

#[test]
fn can_run_from_elf() {
    let memory = Arc::new(Memory::new_from_elf(include_bytes!("../test_data/prng")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let rng = memory
        .try_allocate_type(&UInt16::encrypt_secret(1234, &enc, sk))
        .unwrap();

    let args = ArgsBuilder::new().arg(rng).no_return_value();

    let prog = memory.get_function_entry("xor_shift").unwrap();

    proc.run_program(prog, &memory, args).unwrap();

    let val = memory
        .try_load_type::<UInt16>(rng)
        .unwrap()
        .decrypt(&enc, sk);

    assert_eq!(val, 35300);
}
