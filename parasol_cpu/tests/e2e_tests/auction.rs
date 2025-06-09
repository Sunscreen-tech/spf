use std::{sync::Arc, time::Instant};

use parasol_cpu::{ArgsBuilder, FheComputer, Memory};
use parasol_runtime::{
    Encryption, Evaluation,
    fluent::{DynamicUInt, UInt},
};

use crate::{get_ck, get_sk};

#[test]
fn can_run_auction_from_elf() {
    let memory = Arc::new(Memory::new_from_elf(include_bytes!("../test_data/auction")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let data =
        std::array::from_fn::<_, 8, _>(|i| UInt::<16, _>::encrypt_secret(i as u64, &enc, sk));

    let winner =
        std::array::from_fn::<_, 2, _>(|_| UInt::<16, _>::from(DynamicUInt::new(&enc, 16)));
    let winner = memory.try_allocate_type(&winner).unwrap();

    let a = memory.try_allocate_type(&data).unwrap();

    let args = ArgsBuilder::new()
        .arg(a)
        .arg(data.len() as u16)
        .arg(winner)
        .no_return_value();

    let prog = memory.get_function_entry("auction").unwrap();

    let now = Instant::now();
    proc.run_program(prog, &memory, args).unwrap();
    println!("Runtime {}", now.elapsed().as_secs_f64());

    let winner = memory.try_load_type::<[UInt<16, _>; 2]>(winner).unwrap();

    assert_eq!(winner[0].decrypt(&enc, sk), 7);
    assert_eq!(winner[1].decrypt(&enc, sk), 7);
}
