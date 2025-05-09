use std::sync::Arc;

use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{Encryption, Evaluation, fluent::UInt};

use crate::{get_ck, get_sk};

#[test]
fn can_run_from_elf() {
    env_logger::init();

    let memory = Arc::new(Memory::new_from_elf(include_bytes!("../test_data/vector_add")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let data = std::array::from_fn::<_, 8, _>(|i| UInt::<8, _>::encrypt_secret(i as u64, &enc, sk));

    let a = memory.try_allocate_type(&data).unwrap();
    let b = memory.try_allocate_type(&data).unwrap();
    let c = memory.try_allocate_type(&data).unwrap();

    let args = ArgsBuilder::new().arg(a).arg(b).arg(c).no_return_value();

    let prog = memory.get_function_entry("vector_add").unwrap();

    proc.run_program(prog, &memory, args, 5_000_000).unwrap();

    let result = memory
        .try_load_type::<[UInt<8, _>; 8]>(c)
        .unwrap()
        .map(|r| r.decrypt(&enc, sk) as u8);

    assert_eq!(result, std::array::from_fn(|i| 2 * i as u8));
}
