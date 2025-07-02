use std::sync::{Arc, OnceLock};

use benchmark_system_info::print_system_info;
use criterion::{Criterion, criterion_group, criterion_main};
use parasol_cpu::{ArgsBuilder, CallData, FheComputer, Memory, assembly::IsaOp, register_names::*};
use parasol_runtime::{
    ComputeKey, DEFAULT_128, Encryption, Evaluation, L1GlweCiphertext, SecretKey,
    fluent::{UInt, UInt8},
};
use rayon::ThreadPoolBuilder;

fn setup() -> (Arc<SecretKey>, Encryption, Evaluation) {
    static SK: OnceLock<Arc<SecretKey>> = OnceLock::new();
    static COMPUTE_KEY: OnceLock<Arc<ComputeKey>> = OnceLock::new();

    // Only print system info once
    static PRINTED_SYSTEM_INFO: OnceLock<()> = OnceLock::new();
    PRINTED_SYSTEM_INFO.get_or_init(|| {
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

fn generate_args(enc: &Encryption, sk: &SecretKey) -> CallData<UInt<8, L1GlweCiphertext>> {
    let man = false;
    let smoking = false;
    let diabetic = true;
    let high_bp = true;

    let flags = [man, smoking, diabetic, high_bp]
        .iter()
        .enumerate()
        .map(|(i, &x)| (x as u8) << i)
        .sum::<u8>();

    ArgsBuilder::new()
        .arg(UInt8::encrypt_secret(flags as u128, enc, sk))
        .arg(UInt8::encrypt_secret(40, enc, sk))
        .arg(UInt8::encrypt_secret(50, enc, sk))
        .arg(UInt8::encrypt_secret(70, enc, sk))
        .arg(UInt8::encrypt_secret(170, enc, sk))
        .arg(UInt8::encrypt_secret(1, enc, sk))
        .arg(UInt8::encrypt_secret(1, enc, sk))
        .return_value::<UInt8>()
}

fn _cardio_from_compiler(c: &mut Criterion) {
    let mut group = c.benchmark_group("cardio");
    group.sample_size(10);

    let (sk, enc, eval) = setup();

    group.bench_function("cardio_from_compiler", |bench| {
        bench.iter_batched(
            || {
                let memory = Arc::new(
                    Memory::new_from_elf(include_bytes!("../tests/test_data/cardio")).unwrap(),
                );
                let prog = memory.get_function_entry("cardio").unwrap();
                let args = generate_args(&enc, &sk);
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

pub fn cardio_test_program() -> Vec<IsaOp> {
    let width = 8;

    // Argument registers
    let flags = X33;
    let age = X34;
    let hdl = X35;
    let weight = X36;
    let height = X37;
    let physical_activity = X38;
    let glasses_alcohol = X39;

    // Working registers
    let man = X18;
    let smoking = X19;
    let diabetic = X20;
    let high_bp = X21;
    let cond1 = X22;
    let cond2 = X23;
    let cond3 = X24;
    let cond4 = X25;
    let cond5 = X26;
    let cond6 = X27;
    let cond7 = X28;
    let cond8 = X29;
    let cond9 = X30;
    let cond10 = X31;
    let tmp = T0;
    let result = T1;
    let tmp2 = T2;
    let shift_amount = X32;

    vec![
        IsaOp::Load(flags, SP, 8, 0),
        IsaOp::Load(age, SP, 8, 1),
        IsaOp::Load(hdl, SP, 8, 2),
        IsaOp::Load(weight, SP, 8, 3),
        IsaOp::Load(height, SP, 8, 4),
        IsaOp::Load(physical_activity, SP, 8, 5),
        IsaOp::Load(glasses_alcohol, SP, 8, 6),
        // Truncate the inputs to the specified width
        IsaOp::Trunc(flags, flags, width),
        IsaOp::Trunc(age, age, width),
        IsaOp::Trunc(hdl, hdl, width),
        IsaOp::Trunc(weight, weight, width),
        IsaOp::Trunc(height, height, width),
        IsaOp::Trunc(physical_activity, physical_activity, width),
        IsaOp::Trunc(glasses_alcohol, glasses_alcohol, width),
        // man = get_bit(flags, 0)
        IsaOp::LoadI(shift_amount, 0, 32),
        IsaOp::Shr(tmp, flags, shift_amount),
        IsaOp::LoadI(tmp2, 1, width),
        IsaOp::And(man, tmp, tmp2),
        IsaOp::Trunc(man, man, 1),
        // smoking = get_bit(flags, 1)
        IsaOp::LoadI(shift_amount, 1, 32),
        IsaOp::Shr(tmp, flags, shift_amount),
        IsaOp::LoadI(tmp2, 1, width),
        IsaOp::And(smoking, tmp, tmp2),
        IsaOp::Trunc(smoking, smoking, 1),
        // diabetic = get_bit(flags, 2)
        IsaOp::LoadI(shift_amount, 2, 32),
        IsaOp::Shr(tmp, flags, shift_amount),
        IsaOp::LoadI(tmp2, 1, width),
        IsaOp::And(diabetic, tmp, tmp2),
        IsaOp::Trunc(diabetic, diabetic, 1),
        // high_bp = get_bit(flags, 3)
        IsaOp::LoadI(shift_amount, 3, 32),
        IsaOp::Shr(tmp, flags, shift_amount),
        IsaOp::LoadI(tmp2, 1, width),
        IsaOp::And(high_bp, tmp, tmp2),
        IsaOp::Trunc(high_bp, high_bp, 1),
        // cond1 = man && (age > 50)
        IsaOp::LoadI(tmp, 50, width),
        IsaOp::CmpGt(cond1, age, tmp),
        IsaOp::And(cond1, cond1, man),
        IsaOp::Zext(cond1, cond1, width),
        // cond2 = !man && (age > 60)
        IsaOp::LoadI(tmp, 60, width),
        IsaOp::CmpGt(cond2, age, tmp),
        IsaOp::Not(tmp, man),
        IsaOp::And(cond2, cond2, tmp),
        IsaOp::Zext(cond2, cond2, width),
        // cond3 = smoking
        IsaOp::Move(cond3, smoking),
        IsaOp::Zext(cond3, cond3, width),
        // cond4 = diabetic
        IsaOp::Move(cond4, diabetic),
        IsaOp::Zext(cond4, cond4, width),
        // cond5 = high_bp
        IsaOp::Move(cond5, high_bp),
        IsaOp::Zext(cond5, cond5, width),
        // cond6 = hdl < 40
        IsaOp::LoadI(tmp, 40, width),
        IsaOp::CmpLt(cond6, hdl, tmp),
        IsaOp::Zext(cond6, cond6, width),
        // cond7 = weight > (height - 90)
        IsaOp::LoadI(tmp, 90, width),
        IsaOp::Sub(tmp, height, tmp),
        IsaOp::CmpGt(cond7, weight, tmp),
        IsaOp::Zext(cond7, cond7, width),
        // cond8 = physical_activity < 30
        IsaOp::LoadI(tmp, 30, width),
        IsaOp::CmpLt(cond8, physical_activity, tmp),
        IsaOp::Zext(cond8, cond8, width),
        // cond9 = man && (glasses_alcohol > 3)
        IsaOp::LoadI(tmp, 3, width),
        IsaOp::CmpGt(cond9, glasses_alcohol, tmp),
        IsaOp::And(cond9, cond9, man),
        IsaOp::Zext(cond9, cond9, width),
        // cond10 = !man && (glasses_alcohol > 2)
        IsaOp::LoadI(tmp, 2, width),
        IsaOp::CmpGt(cond10, glasses_alcohol, tmp),
        IsaOp::Not(tmp, man),
        IsaOp::And(cond10, cond10, tmp),
        IsaOp::Zext(cond10, cond10, width),
        // result = sum of all conds
        IsaOp::Add(result, cond1, cond2),
        IsaOp::Add(result, result, cond3),
        IsaOp::Add(result, result, cond4),
        IsaOp::Add(result, result, cond5),
        IsaOp::Add(result, result, cond6),
        IsaOp::Add(result, result, cond7),
        IsaOp::Add(result, result, cond8),
        IsaOp::Add(result, result, cond9),
        IsaOp::Add(result, result, cond10),
        // Return result in A0
        IsaOp::Store(RP, result, 8, 0),
        IsaOp::Ret(),
    ]
}

fn cardio_from_assembly(c: &mut Criterion) {
    let mut group = c.benchmark_group("cardio");
    group.sample_size(10);

    let (sk, enc, eval) = setup();

    group.bench_function("cardio_from_assembly", |bench| {
        bench.iter_batched(
            // Setup closure: runs before each iteration, not timed
            || {
                let memory = Arc::new(Memory::new_default_stack());
                let prog = memory.allocate_program(&cardio_test_program());
                let args = generate_args(&enc, &sk);
                let proc = FheComputer::new(&enc, &eval);
                (proc, args, prog, memory)
            },
            |(mut proc, args, prog, memory)| {
                proc.run_program(prog, &memory, args).unwrap();
                // Check that we get the right answer
                // assert_eq!(result.decrypt(&enc, &sk), 3);
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

fn _cardio_thread_scaling(c: &mut Criterion) {
    fn run_with_threads(c: &mut Criterion, num_threads: usize) {
        let mut group = c.benchmark_group("cardio");
        group.sample_size(10);

        let (sk, enc, eval) = setup();

        group.bench_function(
            format!("Compiled Cardio ({num_threads} threads)"),
            |bench| {
                bench.iter_batched(
                    || {
                        let memory = Arc::new(
                            Memory::new_from_elf(include_bytes!("../tests/test_data/cardio"))
                                .unwrap(),
                        );
                        let prog = memory.get_function_entry("cardio").unwrap();
                        let args = generate_args(&enc, &sk);
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
    //cardio_from_compiler,
    cardio_from_assembly,
    //cardio_thread_scaling
);
criterion_main!(benches);
