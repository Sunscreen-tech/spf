use std::sync::{Arc, OnceLock};

use criterion::{Criterion, criterion_group, criterion_main};
use parasol_cpu::{
    ArgsBuilder, CallData, FheComputer, Memory, Ptr32, assembly::IsaOp, register_names::*,
};
use parasol_runtime::{
    ComputeKey, DEFAULT_128, Encryption, Evaluation, SecretKey, fluent::UInt,
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

fn generate_args<const N: usize>(
    memory: &Memory,
    enc: &Encryption,
    sk: &SecretKey,
) -> (Ptr32, CallData<()>) {
    let data = std::array::from_fn::<_, N, _>(|i| UInt::<16, _>::encrypt_secret(i as u64, enc, sk));
    let winner = std::array::from_fn::<_, 2, _>(|_| UInt::<16, _>::new(enc));

    let winner = memory.try_allocate_type(&winner).unwrap();

    let a = memory.try_allocate_type(&data).unwrap();

    (
        winner,
        ArgsBuilder::new()
            .arg(a)
            .arg(data.len() as u16)
            .arg(winner)
            .no_return_value(),
    )
}

pub fn auction_test_program() -> Vec<IsaOp> {
    let instruction_size = 8;

    // Argument registers
    let bids_ptr = RP; // Pointer to bids array
    let len = A1; // Length of array
    let winner_output_ptr = A2; // Pointer to Winner struct

    // Working registers
    let i = X32; // Loop counter
    let current_bid = X33;
    let winner_output_bid = X34;
    let winner_output_idx = X35;
    let is_winner = X36;
    let one = X37;
    let two = X38;
    let loop_cond = X39;

    let instructions = vec![
        // Truncate len
        IsaOp::Trunc(len, len, 16),
        // Initialize registers
        IsaOp::Load(winner_output_bid, bids_ptr, 16),
        IsaOp::LoadI(winner_output_idx, 0, 16),
        IsaOp::LoadI(i, 1, 16),
        IsaOp::LoadI(one, 1, 16),
        IsaOp::LoadI(two, 2, 32),
        IsaOp::CmpGe(loop_cond, i, len), // LOOP
        IsaOp::BranchNonZero(loop_cond, 8 * instruction_size),
        IsaOp::Add(bids_ptr, bids_ptr, two), // Each bid is 2 bytes
        IsaOp::Load(current_bid, bids_ptr, 16), // bids[i]
        IsaOp::CmpGt(is_winner, current_bid, winner_output_bid), // isWinner = bid[i] >= winningBid->bid
        IsaOp::Cmux(winner_output_bid, is_winner, current_bid, winner_output_bid), // winning_bid = isWinner ? bid[i] : winner_output_bid
        IsaOp::Cmux(winner_output_idx, is_winner, i, winner_output_idx), // winning_idx = isWinner ? i : winner_output_idx
        IsaOp::Add(i, i, one),                                           // i++
        IsaOp::Branch(-8 * instruction_size),                            // Jump back to LOOP
        IsaOp::Store(winner_output_ptr, winner_output_bid, 16), // winningBid->bid = winner_output_bid
        IsaOp::Add(winner_output_ptr, winner_output_ptr, two),
        IsaOp::Trunc(winner_output_idx, winner_output_idx, 16), // Convert index to 16 bits
        IsaOp::Store(winner_output_ptr, winner_output_idx, 16), // winningBid->idx = winner_output_idx
        IsaOp::Ret(),
    ];

    instructions
}

fn auction_from_assembly(c: &mut Criterion) {
    let mut group = c.benchmark_group("auction");
    group.sample_size(10);

    let (sk, enc, eval) = setup();

    group.bench_function("auction_from_assembly_8_bids", |bench| {
        bench.iter_batched(
            || {
                let memory = Arc::new(Memory::new_default_stack());
                let prog = memory.allocate_program(&auction_test_program());
                let (winner, args) = generate_args::<8>(&memory, &enc, &sk);
                let proc = FheComputer::new(&enc, &eval);
                (proc, args, prog, memory, winner)
            },
            |(mut proc, args, prog, memory, _winner)| {
                proc.run_program(prog, &memory, args).unwrap();
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

fn auction_n_bids<const N: usize>(c: &mut Criterion) {
    let mut group = c.benchmark_group("auction");
    group.sample_size(10);

    let (sk, enc, eval) = setup();

    let id = format!("auction_from_compiler_{N}_bids");
    group.bench_function(id, |bench| {
        bench.iter_batched(
            // Setup closure: runs before each iteration, not timed
            || {
                let memory = Arc::new(
                    Memory::new_from_elf(include_bytes!("../tests/test_data/auction")).unwrap(),
                );
                let prog = memory.get_function_entry("auction").unwrap();
                let (winner, args) = generate_args::<N>(&memory, &enc, &sk);
                let proc = FheComputer::new(&enc, &eval);

                (proc, args, prog, memory, winner)
            },
            |(mut proc, args, prog, memory, _winner)| {
                proc.run_program(prog, &memory, args).unwrap();
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

fn auction_thread_scaling(c: &mut Criterion) {
    fn run_with_threads(c: &mut Criterion, num_threads: usize) {
        let mut group = c.benchmark_group("auction");
        group.sample_size(10);

        let (sk, enc, eval) = setup();

        let id = format!("Auction (32 bids, {num_threads} threads)");
        group.bench_function(id, |bench| {
            bench.iter_batched(
                // Setup closure: runs before each iteration, not timed
                || {
                    let memory = Arc::new(
                        Memory::new_from_elf(include_bytes!("../tests/test_data/auction")).unwrap(),
                    );
                    let prog = memory.get_function_entry("auction").unwrap();
                    let (winner, args) = generate_args::<32>(&memory, &enc, &sk);
                    let tp = ThreadPoolBuilder::new()
                        .num_threads(num_threads)
                        .build()
                        .unwrap();
                    let proc = FheComputer::new_with_threadpool(&enc, &eval, Arc::new(tp));

                    (proc, args, prog, memory, winner)
                },
                |(mut proc, args, prog, memory, _winner)| {
                    proc.run_program(prog, &memory, args).unwrap();
                },
                criterion::BatchSize::PerIteration,
            );
        });
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

criterion_group!(
    benches,
    auction_from_assembly,
    auction_n_bids::<2>,
    auction_n_bids::<4>,
    auction_n_bids::<8>,
    auction_n_bids::<16>,
    auction_n_bids::<32>,
    auction_thread_scaling
);
criterion_main!(benches);
