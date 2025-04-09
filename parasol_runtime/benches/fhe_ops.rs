use std::sync::{Arc, OnceLock};

use criterion::{criterion_group, criterion_main, Criterion};
use parasol_runtime::{Encryption, Evaluation, SecretKey, ServerKey, ServerKeyNonFft, DEFAULT_128};
use sunscreen_tfhe::entities::Polynomial;

fn setup() -> (Arc<SecretKey>, Encryption, Evaluation) {
    static SK: OnceLock<Arc<SecretKey>> = OnceLock::new();
    static SERVER_KEY: OnceLock<Arc<ServerKey>> = OnceLock::new();

    let sk = SK
        .get_or_init(|| Arc::new(SecretKey::generate(&DEFAULT_128)))
        .clone();

    let server_key = SERVER_KEY
        .get_or_init(|| {
            let server = ServerKeyNonFft::generate(&sk, &DEFAULT_128);

            Arc::new(server.fft(&DEFAULT_128))
        })
        .clone();

    let enc = Encryption::new(&DEFAULT_128);
    let eval = Evaluation::new(server_key.to_owned(), &DEFAULT_128, &enc);

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
