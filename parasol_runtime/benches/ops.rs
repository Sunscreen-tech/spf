use std::sync::{Arc, OnceLock, mpsc::Receiver};

use criterion::{Criterion, criterion_group, criterion_main};
use parasol_runtime::{
    CircuitProcessor, ComputeKey, ComputeKeyNonFft, DEFAULT_128, Encryption, Evaluation,
    L1GgswCiphertext, L1GlevCiphertext, L1GlweCiphertext, SecretKey,
    fluent::{Bit, CiphertextOps, FheCircuitCtx, Muxable, UInt, UIntGraphNodes},
};

fn make_computer() -> (
    Encryption,
    Arc<SecretKey>,
    CircuitProcessor,
    Receiver<()>,
    Evaluation,
) {
    static SK: OnceLock<Arc<SecretKey>> = OnceLock::new();
    static COMPUTE_KEY: OnceLock<Arc<ComputeKey>> = OnceLock::new();

    let sk = SK
        .get_or_init(|| Arc::new(SecretKey::generate(&DEFAULT_128)))
        .clone();

    let compute_key = COMPUTE_KEY
        .get_or_init(|| {
            let compute = ComputeKeyNonFft::generate(&sk, &DEFAULT_128);

            Arc::new(compute.fft(&DEFAULT_128))
        })
        .clone();

    let enc = Encryption::new(&DEFAULT_128);
    let eval = Evaluation::new(compute_key.to_owned(), &DEFAULT_128, &enc);

    let (uproc, fc) = CircuitProcessor::new(16384, None, &eval, &enc);

    (enc, sk, uproc, fc, eval)
}

fn bench_binary_function<const N: usize, InCt, F>(
    crit: &mut Criterion,
    name: &str,
    op: F,
) where
    InCt: CiphertextOps,
    F: Fn(
        &FheCircuitCtx,
        &UIntGraphNodes<N, L1GgswCiphertext>,
        &UIntGraphNodes<N, L1GgswCiphertext>,
    ),
{
    let (enc, sk, mut uproc, fc, _) = make_computer();

    let ctx = FheCircuitCtx::new();

    // Encrypt inputs with the specified ciphertext type
    let a = UInt::<N, InCt>::encrypt_secret(42 & ((0x1 << N) - 1), &enc, &sk)
        .graph_inputs(&ctx);
    let b = UInt::<N, InCt>::encrypt_secret(35 & ((0x1 << N) - 1), &enc, &sk)
        .graph_inputs(&ctx);

    // Convert to GGSW for computation
    let a = a.convert::<L1GgswCiphertext>(&ctx).into();
    let b = b.convert::<L1GgswCiphertext>(&ctx).into();

    // Apply the operation once
    op(&ctx, &a, &b);

    crit.bench_function(name, |bench| {
        bench.iter(|| {
            uproc
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();
        });
    });
}

fn bench_select_function<const N: usize, InCt>(
    crit: &mut Criterion,
    name: &str,
) where
    InCt: CiphertextOps + Muxable,
{
    let (enc, sk, mut uproc, fc, _) = make_computer();

    let ctx = FheCircuitCtx::new();

    // Selector starts with the same type as inputs, then converts to GGSW
    let selector = Bit::<InCt>::encrypt_secret(true, &enc, &sk)
        .graph_input(&ctx)
        .convert::<L1GgswCiphertext>(&ctx);

    // Encrypt inputs with the specified ciphertext type
    let a = UInt::<N, InCt>::encrypt_secret(42 & ((0x1 << N) - 1), &enc, &sk)
        .graph_inputs(&ctx);
    let b = UInt::<N, InCt>::encrypt_secret(35 & ((0x1 << N) - 1), &enc, &sk)
        .graph_inputs(&ctx);

    // Convert to the same type for select (no conversion needed, already InCt)
    let a: UIntGraphNodes<N, InCt> = a.into();
    let b: UIntGraphNodes<N, InCt> = b.into();

    selector.select_generic(&a, &b, &ctx);

    crit.bench_function(name, |bench| {
        bench.iter(|| {
            uproc
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();
        });
    });
}

fn ops(c: &mut Criterion) {
    fn run_benchmarks<const N: usize>(c: &mut Criterion) {
        // Add benchmarks - GLWE input/output
        bench_binary_function::<N, L1GlweCiphertext, _>(
            c,
            &format!("add-{N}-glwe"),
            |ctx, x, y| {
                x.add::<L1GlweCiphertext>(y, ctx);
            },
        );
        
        // Add benchmarks - GLEV input/output
        bench_binary_function::<N, L1GlevCiphertext, _>(
            c,
            &format!("add-{N}-glev"),
            |ctx, x, y| {
                x.add::<L1GlevCiphertext>(y, ctx);
            },
        );

        // GT benchmarks - GLWE input/output
        bench_binary_function::<N, L1GlweCiphertext, _>(
            c,
            &format!("gt-{N}-glwe"),
            |ctx, x, y| {
                x.gt::<L1GlweCiphertext>(y, ctx);
            },
        );
        
        // GT benchmarks - GLEV input/output
        bench_binary_function::<N, L1GlevCiphertext, _>(
            c,
            &format!("gt-{N}-glev"),
            |ctx, x, y| {
                x.gt::<L1GlevCiphertext>(y, ctx);
            },
        );

        // Mul benchmarks - GLWE input/output
        bench_binary_function::<N, L1GlweCiphertext, _>(
            c,
            &format!("mul-{N}-glwe"),
            |ctx, x, y| {
                x.mul::<L1GlweCiphertext>(y, ctx);
            },
        );
        
        // Mul benchmarks - GLEV input/output
        bench_binary_function::<N, L1GlevCiphertext, _>(
            c,
            &format!("mul-{N}-glev"),
            |ctx, x, y| {
                x.mul::<L1GlevCiphertext>(y, ctx);
            },
        );

        // Select benchmarks - GLWE input/output
        bench_select_function::<N, L1GlweCiphertext>(
            c,
            &format!("select-{N}-glwe"),
        );
        
        // Select benchmarks - GLEV input/output
        bench_select_function::<N, L1GlevCiphertext>(
            c,
            &format!("select-{N}-glev"),
        );
    }

    run_benchmarks::<2>(c);
    run_benchmarks::<4>(c);
    run_benchmarks::<8>(c);
    run_benchmarks::<16>(c);
    run_benchmarks::<32>(c);
    run_benchmarks::<64>(c);
}

criterion_group!(benches, ops);
criterion_main!(benches);
