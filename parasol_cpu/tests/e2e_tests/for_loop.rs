use std::sync::Arc;

use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{Encryption, Evaluation, fluent::UInt};

use crate::{get_ck, get_sk};

#[test]
fn can_run_from_elf() {
    let memory = Arc::new(Memory::new_from_elf(include_bytes!("../test_data/for_loop")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let data =
        std::array::from_fn::<_, 8, _>(|i| UInt::<32, _>::encrypt_secret(i as u128, &enc, sk));

    let a = memory.try_allocate_type(&data).unwrap();

    let args = ArgsBuilder::new()
        .arg(a)
        .arg(8)
        .return_value::<UInt<32, _>>();

    let prog = memory.get_function_entry("for_loop").unwrap();

    let result = proc.run_program(prog, &memory, args).unwrap();

    assert_eq!(result.decrypt(&enc, sk), 28);
}
