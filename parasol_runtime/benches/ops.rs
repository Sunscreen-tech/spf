use std::sync::{mpsc::Receiver, Arc, OnceLock};

use criterion::{criterion_group, criterion_main, Criterion};
use parasol_runtime::{
    fluent::{FheCircuitCtx, UInt, UIntGraphNodes},
    Encryption, Evaluation, L0LweCiphertext, L1GgswCiphertext, L1GlevCiphertext, L1GlweCiphertext,
    SecretKey, ServerKey, ServerKeyFft, UOpProcessor, DEFAULT_128,
};

fn make_computer() -> (
    Encryption,
    Arc<SecretKey>,
    UOpProcessor,
    Receiver<()>,
    Evaluation,
) {
    static SK: OnceLock<Arc<SecretKey>> = OnceLock::new();
    static SERVER_KEY: OnceLock<Arc<ServerKeyFft>> = OnceLock::new();

    let sk = SK
        .get_or_init(|| Arc::new(SecretKey::generate(&DEFAULT_128)))
        .clone();

    let server_key = SERVER_KEY
        .get_or_init(|| {
            let server = ServerKey::generate(&sk, &DEFAULT_128);

            Arc::new(server.fft(&DEFAULT_128))
        })
        .clone();

    let enc = Encryption::new(&DEFAULT_128);
    let eval = Evaluation::new(server_key.to_owned(), &DEFAULT_128, &enc);

    let (uproc, fc) = UOpProcessor::new(16384, None, &eval, &enc);

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

    let a = a.convert::<L1GgswCiphertext>(&ctx);
    let b = b.convert::<L1GgswCiphertext>(&ctx);

    op_glev(&ctx, &a, &b);

    crit.bench_function(&format!("{name} SS+GLEVCmux"), |bench| {
        bench.iter(|| {
            uproc.run_graph_blocking(&ctx.circuit.borrow(), &fc);
        });
    });

    let a = UInt::<N, L0LweCiphertext>::encrypt_secret(42, &enc, &sk).graph_inputs(&ctx);
    let b = UInt::<N, L0LweCiphertext>::encrypt_secret(35, &enc, &sk).graph_inputs(&ctx);

    let a = a.convert::<L1GgswCiphertext>(&ctx);
    let b = b.convert::<L1GgswCiphertext>(&ctx);

    op_glwe(&ctx, &a, &b);

    crit.bench_function(&format!("{name} CBS+GLWECMux"), |bench| {
        bench.iter(|| {
            uproc.run_graph_blocking(&ctx.circuit.borrow(), &fc);
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
                x.gt::<N, L1GlevCiphertext>(y, ctx);
            },
            |ctx, x, y| {
                x.gt::<N, L1GlweCiphertext>(y, ctx);
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

    //run_benchmarks::<8>(c);
    run_benchmarks::<16>(c);
    run_benchmarks::<32>(c);
    run_benchmarks::<64>(c);
    //run_benchmarks::<256>(c);
}

criterion_group!(benches, ops);
criterion_main!(benches);
