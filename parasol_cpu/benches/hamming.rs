use std::sync::{Arc, OnceLock};

use criterion::{Criterion, criterion_group, criterion_main};
use parasol_cpu::{Args, ArgsBuilder, FheComputer, Memory, assembly::IsaOp, register_names::*};
use parasol_runtime::{
    ComputeKey, DEFAULT_128, Encryption, Evaluation, L1GlweCiphertext, SecretKey, fluent::UInt,
    metadata::print_system_info,
};
use rayon::ThreadPoolBuilder;

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

fn generate_args(
    memory: &Memory,
    enc: &Encryption,
    sk: &SecretKey,
    len: usize,
) -> Args<UInt<8, L1GlweCiphertext>> {
    let a = 0xFEEDF00D_CAFEBABEu64
        .to_le_bytes()
        .map(|x| UInt::<8, _>::encrypt_secret(x as u64, enc, sk));
    let b = 0x12345678_9ABCDEF0u64
        .to_le_bytes()
        .map(|x| UInt::<8, _>::encrypt_secret(x as u64, enc, sk));

    let a = memory.try_allocate_type(&a).unwrap();
    let b = memory.try_allocate_type(&b).unwrap();

    ArgsBuilder::new()
        .arg(a)
        .arg(b)
        .arg(len as u8)
        .return_value::<UInt<8, _>>()
}

fn hamming_from_compiler(c: &mut Criterion) {
    let mut group = c.benchmark_group("hamming");
    group.sample_size(10);

    let (sk, enc, eval) = setup();

    group.bench_function("hamming_from_compiler", |bench| {
        bench.iter_batched(
            // Setup closure: runs before each iteration, not timed
            || {
                let memory = Arc::new(
                    Memory::new_from_elf(include_bytes!("../tests/test_data/hamming_distance"))
                        .unwrap(),
                );
                let prog = memory.get_function_entry("hamming_distance").unwrap();
                let args = generate_args(&memory, &enc, &sk, 8);
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

pub fn hamming_test_program() -> Vec<IsaOp> {
    let instruction_size = 8;

    // Argument registers
    let a_ptr = A0;
    let b_ptr = A1;
    let len = A2;

    // Working registers
    let i = X32;
    let j = X33;
    let zero_u8 = X34;
    let one_u8 = X35;
    let one_u32 = X36;
    let eight_u32 = X37;

    let a_i = X38;
    let b_i = X39;

    let a_i_j = X40;
    let b_i_j = X41;

    let distance = X42;
    let distance_add = X43;
    let bits_unequal = X44;
    let i_compare = X45;
    let j_compare = X46;

    let instructions = vec![
        // Initialize values
        IsaOp::LoadI(zero_u8, 0, 8),
        IsaOp::LoadI(one_u8, 1, 8),
        IsaOp::LoadI(one_u32, 1, 32),
        IsaOp::LoadI(eight_u32, 8, 32),
        IsaOp::LoadI(distance, 0, 8),
        IsaOp::LoadI(i, 0, 32),    // Loop I initialization
        IsaOp::Add(a_i, a_ptr, i), //** LOOP_I
        IsaOp::Add(b_i, b_ptr, i),
        IsaOp::Load(a_i, a_i, 8),                 // Load a[i]
        IsaOp::Load(b_i, b_i, 8),                 // Load b[i]
        IsaOp::LoadI(j, 0, 32),                   // Loop J initialization
        IsaOp::Shr(a_i_j, a_i, j),                // |** LOOP_J
        IsaOp::Trunc(a_i_j, a_i_j, 8),            // |
        IsaOp::And(a_i_j, a_i_j, one_u8),         // |
        IsaOp::Trunc(a_i_j, a_i_j, 1),            // > get_bit(a[i], j)
        IsaOp::Shr(b_i_j, b_i, j),                // |
        IsaOp::Trunc(b_i_j, b_i_j, 8),            // |
        IsaOp::And(b_i_j, b_i_j, one_u8),         // |
        IsaOp::Trunc(b_i_j, b_i_j, 1),            // > get_bit(b[i], j)
        IsaOp::CmpEq(bits_unequal, a_i_j, b_i_j), // |
        IsaOp::Not(bits_unequal, bits_unequal),   // > bits_unequal = a[i][j] != b[i][j]
        IsaOp::Cmux(distance_add, bits_unequal, one_u8, zero_u8), // > distance_add = bits_unequal ? 1 : 0
        IsaOp::Add(distance, distance, distance_add),             // > distance += distance_add
        IsaOp::Add(j, j, one_u32),                                // > j += 1
        IsaOp::CmpLt(j_compare, j, eight_u32),                    // > j < 8
        IsaOp::BranchNonZero(j_compare, -14 * instruction_size),  //** Loop J end
        IsaOp::Add(i, i, one_u32),                                // > i += 1
        IsaOp::CmpLt(i_compare, i, len),                          // > i < len
        IsaOp::BranchNonZero(i_compare, -22 * instruction_size),  //** Loop I end
        IsaOp::Move(A0, distance),                                // Move result to output register
        IsaOp::Ret(),
    ];

    instructions
}

fn hamming_from_assembly(c: &mut Criterion) {
    let mut group = c.benchmark_group("hamming");
    group.sample_size(10);

    let (sk, enc, eval) = setup();

    group.bench_function("hamming_from_assembly", |bench| {
        bench.iter_batched(
            || {
                let memory = Arc::new(Memory::new_default_stack());
                let prog = memory.allocate_program(&hamming_test_program());
                let args = generate_args(&memory, &enc, &sk, 8);
                let proc = FheComputer::new(&enc, &eval);
                (proc, args, prog, memory)
            },
            |(mut proc, args, prog, memory)| {
                let _result = proc.run_program(prog, &memory, args).unwrap();
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

fn hamming_thread_scaling(c: &mut Criterion) {
    fn run_with_threads(c: &mut Criterion, num_threads: usize) {
        let (sk, enc, eval) = setup();

        let mut g = c.benchmark_group("Thread scaling");
        g.sample_size(10);

        g.bench_function(
            format!("Compiled Hamming distance ({num_threads} threads)"),
            |bench| {
                bench.iter_batched(
                    // Setup closure: runs before each iteration, not timed
                    || {
                        let memory = Arc::new(
                            Memory::new_from_elf(include_bytes!(
                                "../tests/test_data/hamming_distance"
                            ))
                            .unwrap(),
                        );
                        let prog = memory.get_function_entry("hamming_distance").unwrap();
                        let args = generate_args(&memory, &enc, &sk, 8);

                        let tp = ThreadPoolBuilder::new()
                            .num_threads(num_threads)
                            .build()
                            .unwrap();

                        let proc = FheComputer::new_with_threadpool(&enc, &eval, Arc::new(tp));

                        (proc, args, prog, memory)
                    },
                    |(mut proc, args, prog, memory)| {
                        proc.run_program(prog, &memory, args).unwrap();
                    },
                    criterion::BatchSize::PerIteration,
                );
            },
        );
    }

    let mut num_threads = 1;
    let num_cores = num_cpus::get_physical();

    loop {
        run_with_threads(c, num_threads);

        if num_threads == num_cores {
            break;
        }

        num_threads = usize::min(num_threads * 2, num_cpus::get_physical());
    }
}

fn hamming_input_scaling(c: &mut Criterion) {
    fn run_input_len(c: &mut Criterion, len: usize) {
        let mut group = c.benchmark_group("hamming");
        group.sample_size(10);

        let (sk, enc, eval) = setup();

        group.bench_function(format!("Hamming input scaling ({len} inputs)"), |bench| {
            bench.iter_batched(
                // Setup closure: runs before each iteration, not timed
                || {
                    let memory = Arc::new(
                        Memory::new_from_elf(include_bytes!("../tests/test_data/hamming_distance"))
                            .unwrap(),
                    );
                    let prog = memory.get_function_entry("hamming_distance").unwrap();
                    let args = generate_args(&memory, &enc, &sk, len);
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

    run_input_len(c, 1);
    run_input_len(c, 2);
    run_input_len(c, 4);
    run_input_len(c, 8);
}

criterion_group!(
    benches,
    hamming_from_compiler,
    hamming_from_assembly,
    hamming_thread_scaling,
    hamming_input_scaling
);
criterion_main!(benches);
