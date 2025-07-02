use std::sync::{Arc, OnceLock};

use benchmark_system_info::print_system_info;
use criterion::{Criterion, criterion_group, criterion_main};
use parasol_cpu::{
    ArgsBuilder, CallData, FheComputer, Memory, Ptr32, assembly::IsaOp, register_names::*,
};
use parasol_runtime::{
    ComputeKey, DEFAULT_128, Encryption, Evaluation, L1GlweCiphertext, SecretKey,
    fluent::{UInt, UInt16},
};
use rayon::ThreadPoolBuilder;

fn setup() -> (Arc<SecretKey>, Encryption, Evaluation) {
    static SK: OnceLock<Arc<SecretKey>> = OnceLock::new();
    static COMPUTE_KEY: OnceLock<Arc<ComputeKey>> = OnceLock::new();

    // Only print system info once
    static PRINTED_SYSTEM_INFO: OnceLock<()> = OnceLock::new();
    PRINTED_SYSTEM_INFO.get_or_init(|| {
        print_system_info();
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
) -> (CallData<[UInt<16, L1GlweCiphertext>; 4]>, Ptr32) {
    let result = memory
        .try_allocate(std::mem::size_of::<[u16; 4]>() as u32)
        .unwrap();

    let args = ArgsBuilder::new()
        .arg(UInt16::encrypt_secret(2, enc, sk))
        .arg(UInt16::encrypt_secret(7, enc, sk))
        .arg(UInt16::encrypt_secret(9, enc, sk))
        .return_value::<[UInt16; 4]>();

    (args, result)
}

fn _chi_squared_from_compiler(c: &mut Criterion) {
    let mut group = c.benchmark_group("chi_squared");
    group.sample_size(10);

    let (sk, enc, eval) = setup();

    group.bench_function("chi_squared_from_compiler", |bench| {
        bench.iter_batched(
            // Setup closure: runs before each iteration, not timed
            || {
                let memory = Arc::new(
                    Memory::new_from_elf(include_bytes!("../tests/test_data/chi_sq")).unwrap(),
                );
                let prog = memory.get_function_entry("chi_sq").unwrap();
                let (args, _) = generate_args(&memory, &enc, &sk);
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

pub fn chi_sq_test_program() -> Vec<IsaOp> {
    let width = 16; // Use 16-bit width for the integers

    let n_0 = X18; // n_0
    let n_1 = X19; // n_1
    let n_2 = X20; // n_2

    let a = X22;
    let x = X23;
    let y = X24;

    vec![
        // Load our inputs.
        IsaOp::Load(n_0, SP, width, 0),
        IsaOp::Load(n_1, SP, width, (width / 8) as i32),
        IsaOp::Load(n_2, SP, width, (2 * width / 8) as i32),
        //

        // a = 4 * n_0 * n_2 - n_1 * n_1;
        IsaOp::LoadI(T0, 4, width), // T0 = 4
        IsaOp::Mul(T0, T0, n_0),    // T0 = 4 * n_0
        IsaOp::Mul(T0, T0, n_2),    // T0 = 4 * n_0 * n_2
        IsaOp::Mul(T1, n_1, n_1),   // T1 = n_1 * n_1
        IsaOp::Sub(a, T0, T1),      // a = 4 * n_0 * n_2 - n_1 * n_1
        //

        // x = 2 * n_0 + n_1;
        IsaOp::LoadI(T1, 2, width), // T1 = 2
        IsaOp::Mul(T1, T1, n_0),    // T1 = 2 * n_0
        IsaOp::Add(x, T1, n_1),     // x = (2 * n_0) + n_1
        //

        // y = 2 * n_2 + n_1;
        IsaOp::LoadI(T2, 2, width), // T2 = 2
        IsaOp::Mul(T2, T2, n_2),    // T2 = 2 * n_2
        IsaOp::Add(y, T2, n_1),     // y = (2 * n_2) + n_1
        //

        // res->alpha = a * a;
        IsaOp::Mul(T3, a, a),           // T3 = a * a
        IsaOp::Store(RP, T3, width, 0), // res->alpha = T3
        //

        // res->b_1 = 2 * x * x;
        IsaOp::Mul(T4, x, x),                            // T4 = x * x
        IsaOp::LoadI(T6, 2, width),                      // T6 = 2
        IsaOp::Mul(T4, T4, T6),                          // T4 = (x * x) * 2
        IsaOp::Store(RP, T4, width, (width / 8) as i32), // res->b_1 = T4
        //

        // res->b_2 = x * y;
        IsaOp::Mul(T5, x, y),                                // T5 = x * y
        IsaOp::Store(RP, T5, width, (2 * width / 8) as i32), // res->b_2 = T5
        //

        // res->b_3 = 2 * y * y;
        IsaOp::Mul(T6, y, y),                                // T6 = y * y
        IsaOp::LoadI(T5, 2, width),                          // T5 = 2
        IsaOp::Mul(T6, T5, T6),                              // T6 = (y * y) * 2
        IsaOp::Store(RP, T6, width, (3 * width / 8) as i32), // res->b_3
        //
        IsaOp::Ret(),
    ]
}

fn chi_squared_from_assembly(c: &mut Criterion) {
    let mut group = c.benchmark_group("chi_squared");
    group.sample_size(10);

    let (sk, enc, eval) = setup();

    group.bench_function("chi_squared_from_assembly", |bench| {
        bench.iter_batched(
            || {
                let memory = Arc::new(Memory::new_default_stack());
                let prog = memory.allocate_program(&chi_sq_test_program());
                let (args, _) = generate_args(&memory, &enc, &sk);
                let proc = FheComputer::new(&enc, &eval);

                (proc, args, prog, memory)
            },
            |(mut proc, args, prog, memory)| {
                let _ = proc.run_program(prog, &memory, args).unwrap();

                // Check that we got the right answer.
                // assert_eq!(result[0].decrypt(&enc, &sk), 529);
                // assert_eq!(result[1].decrypt(&enc, &sk), 242);
                // assert_eq!(result[2].decrypt(&enc, &sk), 275);
                // assert_eq!(result[3].decrypt(&enc, &sk), 1250);
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

fn _chi_squared_thread_scaling(c: &mut Criterion) {
    fn run_with_threads(c: &mut Criterion, num_threads: usize) {
        let mut group = c.benchmark_group("chi_squared");
        group.sample_size(10);

        let (sk, enc, eval) = setup();

        group.bench_function(
            format!("Compiled chi squared ({num_threads} threads)"),
            |bench| {
                bench.iter_batched(
                    // Setup closure: runs before each iteration, not timed
                    || {
                        let memory = Arc::new(
                            Memory::new_from_elf(include_bytes!("../tests/test_data/chi_sq"))
                                .unwrap(),
                        );
                        let prog = memory.get_function_entry("chi_sq").unwrap();
                        let (args, _) = generate_args(&memory, &enc, &sk);
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

// TODO: Need updated calling convention in compiler to re-enable benchmarks
criterion_group!(
    benches,
    // chi_squared_from_compiler,
    chi_squared_from_assembly,
    // chi_squared_thread_scaling
);
criterion_main!(benches);
