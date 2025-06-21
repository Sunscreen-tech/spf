use std::sync::{Arc, OnceLock};

use criterion::{Criterion, criterion_group, criterion_main};
use parasol_cpu::{ArgsBuilder, CallData, FheComputer, Memory};
use parasol_runtime::{
    ComputeKey, DEFAULT_128, Encryption, Evaluation, SecretKey, fluent::UInt,
    metadata::print_system_info,
};

fn setup() -> (Arc<SecretKey>, Encryption, Evaluation) {
    static SK: OnceLock<Arc<SecretKey>> = OnceLock::new();
    static COMPUTE_KEY: OnceLock<Arc<ComputeKey>> = OnceLock::new();

    // Only print system info once
    static PRINTED_SYSTEM_INFO: OnceLock<()> = OnceLock::new();
    PRINTED_SYSTEM_INFO.get_or_init(|| {
        env_logger::init();
        print_system_info();

        println!("Parameters (DEFAULT_128):");
        let params_json = serde_json::to_string_pretty(&DEFAULT_128).unwrap();
        println!("{params_json}");
    });

    let sk = SK
        .get_or_init(|| Arc::new(SecretKey::generate(&DEFAULT_128)))
        .clone();

    let compute_key = COMPUTE_KEY
        .get_or_init(|| Arc::new(ComputeKey::generate(&sk, &DEFAULT_128)))
        .clone();

    let enc = Encryption::new(&DEFAULT_128);
    let eval = Evaluation::new(compute_key.to_owned(), &DEFAULT_128, &enc);

    (sk, enc, eval)
}

fn generate_args(memory: &Memory, enc: &Encryption, sk: &SecretKey) -> CallData<()> {
    let sender = memory
        .try_allocate_type(&UInt::<32, _>::encrypt_secret(42, enc, sk))
        .unwrap();
    let receiver = memory
        .try_allocate_type(&UInt::<32, _>::encrypt_secret(29, enc, sk))
        .unwrap();

    ArgsBuilder::new()
        .arg(sender)
        .arg(receiver)
        .arg(UInt::<32, _>::encrypt_secret(26, enc, sk))
        .no_return_value()
}

fn transfer_from_compiler(c: &mut Criterion) {
    let mut group = c.benchmark_group("transfer");
    group.sample_size(10);

    let (sk, enc, eval) = setup();

    group.bench_function("transfer_from_compiler", |bench| {
        bench.iter_batched(
            // Setup closure: runs before each iteration, not timed
            || {
                let memory = Arc::new(
                    Memory::new_from_elf(include_bytes!("../tests/test_data/transfer")).unwrap(),
                );
                let prog = memory.get_function_entry("transfer").unwrap();
                let args = generate_args(&memory, &enc, &sk);
                let proc = FheComputer::new(&enc, &eval);

                (proc, args, prog, memory)
            },
            |(mut proc, args, prog, memory)| {
                proc.run_program(prog, &memory, args).unwrap();
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

criterion_group!(benches, transfer_from_compiler);
criterion_main!(benches);
