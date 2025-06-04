use std::sync::{Arc, OnceLock};

use criterion::{Criterion, criterion_group, criterion_main};
use parasol_cpu::{
    Args, ArgsBuilder, FheComputer, Memory, Ptr32, RunProgramOptionsBuilder, assembly::IsaOp,
    register_names::*,
};
use parasol_runtime::{
    ComputeKey, DEFAULT_128, Encryption, Evaluation, L1GlweCiphertext, SecretKey, fluent::UInt,
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
        println!("{}", params_json);
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

fn generate_args(memory: &Memory, enc: &Encryption, sk: &SecretKey) -> (Ptr32, Args<()>) {
    let data =
        std::array::from_fn::<_, 8, _>(|i| UInt::<16, _>::encrypt_secret(i as u64, &enc, sk));

    let winner = std::array::from_fn::<_, 2, _>(|_| UInt::<16, _>::new(&enc));
    let winner = memory.try_allocate_type(&winner).unwrap();

    let a = memory.try_allocate_type(&data).unwrap();

    (
        winner,
        ArgsBuilder::new()
            .arg(a)
            .arg(data.len() as u32)
            .arg(winner)
            .no_return_value(),
    )
}

fn auction_from_compiler(c: &mut Criterion) {
    let mut group = c.benchmark_group("auction");
    group.sample_size(10);

    let (sk, enc, eval) = setup();

    group.bench_function("auction_from_compiler", |bench| {
        bench.iter_batched(
            // Setup closure: runs before each iteration, not timed
            || {
                let memory = Arc::new(
                    Memory::new_from_elf(include_bytes!("../tests/test_data/auction")).unwrap(),
                );
                let prog = memory.get_function_entry("auction").unwrap();
                let (winner, args) = generate_args(&memory, &enc, &sk);
                let proc = FheComputer::new(&enc, &eval);

                (proc, args, prog, memory, winner)
            },
            |(mut proc, args, prog, memory, winner)| {
                proc.run_program(prog, &memory, args).unwrap();

                // let winner = memory.try_load_type::<[UInt<16, _>; 2]>(winner).unwrap();
                // assert_eq!(winner[0].decrypt(&enc, &sk), 7);
                // assert_eq!(winner[1].decrypt(&enc, &sk), 7);
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

pub fn auction_test_program() -> Vec<IsaOp> {
    let width = 16; // Using uint16_t for bids and winner fields
    let instruction_size = 8;

    // Argument registers
    let bids_ptr = A0; // Pointer to bids array
    let len = A1; // Length of array
    let winner_output_ptr = A2; // Pointer to Winner struct

    // Working registers
    let i = X32; // Loop counter
    let current_bid = X33;
    let current_idx = X34;
    let winner_output_bid = X35;
    let winner_output_idx = X36;
    let is_winner = X37;
    let bid_at_i = X39;
    let offset_to_ptr_i = X40;
    let one = X41;
    let loop_cond = X42;
    let bid_pointer_increment = X43;
    let idx_increment = X44;
    let bid_offset_to_ptr_i = X45;

    let instructions = vec![
        // Truncate len to be 16 bits
        ("", IsaOp::Trunc(len, len, width)),
        // We will be iterating over the bids, which involves adding this offset
        ("", IsaOp::LoadI(bid_pointer_increment, width * 2 / 8, 32)),
        // Offset to the idx field in the Winner strict.
        ("", IsaOp::LoadI(idx_increment, width / 8, 32)),
        ("", IsaOp::LoadI(one, 1, width)),
        // Load first bid into winner (bids[0])
        ("", IsaOp::Load(current_bid, bids_ptr, width)),
        // Initialize winner_output_idx = 0
        ("", IsaOp::LoadI(current_idx, 0, width)),
        // Get the pointer for the Winner->bid field
        ("", IsaOp::Move(winner_output_bid, winner_output_ptr)),
        // Get the pointer for the Winner->idx field
        (
            "",
            IsaOp::Add(winner_output_idx, winner_output_ptr, idx_increment),
        ),
        // Store initial winner_output_bid to Winner.bid
        ("", IsaOp::Store(winner_output_bid, current_bid, width)),
        ("", IsaOp::Store(winner_output_idx, current_idx, width)),
        // Initialize counter i = 1 (we start from second element)
        ("", IsaOp::LoadI(i, 1, width)),
        ("loop", IsaOp::CmpLt(loop_cond, i, len)),
        // Skip to end if i >= len
        ("", IsaOp::BranchZero(loop_cond, 13 * instruction_size)),
        // Expand i to 32
        ("", IsaOp::Zext(i, i, 32)),
        ("", IsaOp::Mul(offset_to_ptr_i, i, bid_pointer_increment)),
        ("", IsaOp::Trunc(i, i, width)),
        // Load the bid at index i
        (
            "",
            IsaOp::Add(bid_offset_to_ptr_i, bids_ptr, offset_to_ptr_i),
        ),
        ("", IsaOp::Load(bid_at_i, bid_offset_to_ptr_i, width)),
        // Check for the higher bid
        ("", IsaOp::CmpGe(is_winner, bid_at_i, current_bid)),
        // If bid_at_i > current_bid, update winner
        (
            "",
            IsaOp::Cmux(current_bid, is_winner, bid_at_i, current_bid),
        ),
        ("", IsaOp::Cmux(current_idx, is_winner, i, current_idx)),
        // Load the current bid for the next iteration
        ("", IsaOp::Store(winner_output_bid, current_bid, width)),
        ("", IsaOp::Store(winner_output_idx, current_idx, width)),
        // Increment i
        ("", IsaOp::Add(i, i, one)),
        // Jump back to the loop start
        ("", IsaOp::Branch(-13 * instruction_size)), // FIX
        ("return", IsaOp::Ret()),
    ];

    instructions.into_iter().map(|x| x.1).collect()
}

fn auction_from_assembly(c: &mut Criterion) {
    let mut group = c.benchmark_group("auction");
    group.sample_size(10);

    let (sk, enc, eval) = setup();

    group.bench_function("auction_from_assembly", |bench| {
        bench.iter_batched(
            // Setup closure: runs before each iteration, not timed
            || {
                let memory = Arc::new(Memory::new_default_stack());
                let prog = memory.allocate_program(&auction_test_program());
                let (winner, args) = generate_args(&memory, &enc, &sk);
                let proc = FheComputer::new(&enc, &eval);
                (proc, args, prog, memory, winner)
            },
            |(mut proc, args, prog, memory, winner)| {
                // let options = RunProgramOptionsBuilder::new()
                //     .log_instruction_execution(true)
                //     .log_register_info(false)
                //     .build();
                // let dummy_options = RunProgramOptionsBuilder::new()
                //     .log_instruction_execution(false)
                //     .log_register_info(false)
                //     .build();
                // proc.run_program_with_options(prog, &memory, args, &options)
                //     .unwrap();
                // proc.run_program_with_options(prog, &memory, args, &dummy_options)
                //     .unwrap();

                proc.run_program(prog, &memory, args).unwrap();

                let winner = memory.try_load_type::<[UInt<16, _>; 2]>(winner).unwrap();
                assert_eq!(winner[0].decrypt(&enc, &sk), 7);
                assert_eq!(winner[1].decrypt(&enc, &sk), 7);
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

criterion_group!(
    benches,
    // auction_from_compiler,
    auction_from_assembly
);
criterion_main!(benches);
