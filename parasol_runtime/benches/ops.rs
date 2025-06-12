use std::sync::{Arc, OnceLock, mpsc::Receiver};

use criterion::{Criterion, criterion_group, criterion_main};
use parasol_runtime::{
    CircuitProcessor, ComputeKey, ComputeKeyNonFft, DEFAULT_128, Encryption, Evaluation,
    L0LweCiphertext, L1GgswCiphertext, L1GlevCiphertext, L1GlweCiphertext, SecretKey,
    fluent::{FheCircuitCtx, UInt, UIntGraphNodes},
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

fn bench_binary_function<const N: usize, F1, F2>(
    crit: &mut Criterion,
    name: &str,
    op_glev: F1,
    op_glwe: F2,
) where
    F1: Fn(
        &FheCircuitCtx,
        &UIntGraphNodes<N, L1GgswCiphertext>,
        &UIntGraphNodes<N, L1GgswCiphertext>,
    ),
    F2: Fn(
        &FheCircuitCtx,
        &UIntGraphNodes<N, L1GgswCiphertext>,
        &UIntGraphNodes<N, L1GgswCiphertext>,
    ),
{
    let (enc, sk, mut uproc, fc, _) = make_computer();

    let ctx = FheCircuitCtx::new();

    let a = UInt::<N, L1GlevCiphertext>::encrypt_secret(42, &enc, &sk).graph_inputs(&ctx);
    let b = UInt::<N, L1GlevCiphertext>::encrypt_secret(35, &enc, &sk).graph_inputs(&ctx);

    let a = a.convert::<L1GgswCiphertext>(&ctx).into();
    let b = b.convert::<L1GgswCiphertext>(&ctx).into();

    op_glev(&ctx, &a, &b);

    // crit.bench_function(&format!("{name} SS+GLEVCmux"), |bench| {
    //     bench.iter(|| {
    //         uproc.run_graph_blocking(&ctx.circuit.borrow(), &fc);
    //     });
    // });

    let ctx = FheCircuitCtx::new();

    let a = UInt::<N, L0LweCiphertext>::encrypt_secret(42, &enc, &sk).graph_inputs(&ctx);
    let b = UInt::<N, L0LweCiphertext>::encrypt_secret(35, &enc, &sk).graph_inputs(&ctx);

    let a = a.convert::<L1GgswCiphertext>(&ctx).into();
    let b = b.convert::<L1GgswCiphertext>(&ctx).into();

    op_glwe(&ctx, &a, &b);

    crit.bench_function(&format!("{name} CBS+GLWECMux"), |bench| {
        bench.iter(|| {
            uproc
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();
        });
    });
}

fn ops(c: &mut Criterion) {
    fn run_benchmarks<const N: usize>(c: &mut Criterion) {
        bench_binary_function::<N, _, _>(
            c,
            &format!("add-{N}"),
            |ctx, x, y| {
                x.add::<L1GlevCiphertext>(y, ctx);
            },
            |ctx, x, y| {
                x.add::<L1GlweCiphertext>(y, ctx);
            },
        );

        bench_binary_function::<N, _, _>(
            c,
            &format!("gt-{N}"),
            |ctx, x, y| {
                x.gt::<L1GlevCiphertext>(y, ctx);
            },
            |ctx, x, y| {
                x.gt::<L1GlweCiphertext>(y, ctx);
            },
        );

        bench_binary_function::<N, _, _>(
            c,
            &format!("mul-{N}"),
            |ctx, x, y| {
                x.mul::<L1GlevCiphertext>(y, ctx);
            },
            |ctx, x, y| {
                x.mul::<L1GlweCiphertext>(y, ctx);
            },
        );
    }

    run_benchmarks::<8>(c);
    run_benchmarks::<16>(c);
    run_benchmarks::<32>(c);
    run_benchmarks::<64>(c);
    //run_benchmarks::<256>(c);
}

criterion_group!(benches, ops);
criterion_main!(benches);
