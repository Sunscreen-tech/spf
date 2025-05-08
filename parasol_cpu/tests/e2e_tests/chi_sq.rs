use std::sync::Arc;

use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{ComputeKey, Encryption, Evaluation, SecretKey, fluent::UInt};

use crate::{get_ck, get_sk};

#[test]
fn can_run_from_elf() {
    let memory = Arc::new(Memory::new_from_elf(include_bytes!("../test_data/chi_sq")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let result = memory
        .try_allocate(std::mem::size_of::<[u16; 4]>() as u32)
        .unwrap();

    let args = ArgsBuilder::new()
        .arg(UInt::<16, _>::encrypt_secret(2, &enc, &sk))
        .arg(UInt::<16, _>::encrypt_secret(7, &enc, &sk))
        .arg(UInt::<16, _>::encrypt_secret(9, &enc, &sk))
        .arg(result)
        .no_return_value();

    let prog = memory.get_function_entry("chi_sq").unwrap();

    proc.run_program(prog, &memory, args, 3_000_000).unwrap();

    let result = memory.try_load_type::<[UInt<16, _>; 4]>(result).unwrap();

    assert_eq!(result[0].decrypt(&enc, &sk), 529);
    assert_eq!(result[1].decrypt(&enc, &sk), 242);
    assert_eq!(result[2].decrypt(&enc, &sk), 275);
    assert_eq!(result[3].decrypt(&enc, &sk), 1250);
}
