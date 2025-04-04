use std::sync::{Arc, OnceLock};

use criterion::{Criterion, criterion_group, criterion_main};
use parasol_runtime::{
    ComputeKey, ComputeKeyNonFft, DEFAULT_128, Encryption, Evaluation, SecretKey,
};
use sunscreen_tfhe::entities::Polynomial;

fn setup() -> (Arc<SecretKey>, Encryption, Evaluation) {
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

    (sk, enc, eval)
}

fn ops(c: &mut Criterion) {
    let (sk, enc, eval) = setup();

    let sel = enc.encrypt_ggsw_l1_secret(true, &sk);
    let a = enc.encrypt_glwe_l1_secret(&Polynomial::zero(DEFAULT_128.l1_poly_degree().0), &sk);
    let b = enc.encrypt_glwe_l1_secret(&Polynomial::zero(DEFAULT_128.l1_poly_degree().0), &sk);

    let mut result = enc.allocate_glwe_l1();

    c.bench_function("CMux", |bench| {
        bench.iter(|| {
            eval.cmux(&mut result, &sel, &a, &b);
        });
    });

    let a = enc.encrypt_glev_l1_secret(&Polynomial::zero(DEFAULT_128.l1_poly_degree().0), &sk);
    let b = enc.encrypt_glev_l1_secret(&Polynomial::zero(DEFAULT_128.l1_poly_degree().0), &sk);

    let mut result = enc.allocate_glev_l1();

    c.bench_function("GLEV cmux", |bench| {
        bench.iter(|| {
            eval.glev_cmux(&mut result, &sel, &a, &b);
        });
    });

    let a = enc.encrypt_glev_l1_secret(&Polynomial::zero(DEFAULT_128.l1_poly_degree().0), &sk);

    let mut result = enc.allocate_ggsw_l1();

    c.bench_function("Scheme switch", |bench| {
        bench.iter(|| {
            eval.scheme_switch(&mut result, &a);
        });
    });

    let a = enc.encrypt_lwe_l0_secret(false, &sk);

    let mut result = enc.allocate_ggsw_l1();

    c.bench_function("Circuit bootstrap", |bench| {
        bench.iter(|| {
            eval.circuit_bootstrap(&mut result, &a);
        });
    });

    let a = enc.encrypt_lwe_l1_secret(false, &sk);

    let mut result = enc.allocate_lwe_l0();

    c.bench_function("Keyswitch", |bench| {
        bench.iter(|| {
            eval.keyswitch_lwe_l1_lwe_l0(&mut result, &a);
        });
    });
}

criterion_group!(benches, ops);
criterion_main!(benches);
