use std::{collections::HashMap, sync::{Arc, OnceLock}};

use criterion::{Criterion, criterion_group, criterion_main};
use dashmap::DashMap;
use parasol_runtime::{
    ComputeKey, ComputeKeyNonFft, DEFAULT_128, Encryption, Evaluation, FAST_BIG_128, Params,
    SecretKey, TURBO_CHUNGUS_128,
};
use sunscreen_tfhe::entities::Polynomial;

fn get_keys(params: &Params) -> (Arc<SecretKey>, Encryption, Evaluation) {
    static SK: OnceLock<DashMap<Params, OnceLock<Arc<SecretKey>>>> = OnceLock::new();
    static COMPUTE_KEY: OnceLock<DashMap<Params, OnceLock<Arc<ComputeKey>>>> = OnceLock::new();

    let sk_cache = SK.get_or_init(|| DashMap::new());

    let sk = sk_cache
        .entry(params.clone())
        .or_default()
        .get_or_init(|| Arc::new(SecretKey::generate(params)))
        .clone();

    let ck_cache = COMPUTE_KEY.get_or_init(|| DashMap::new());

    let compute_key = ck_cache
        .entry(params.clone())
        .or_default()
        .get_or_init(|| {
            let compute = ComputeKeyNonFft::generate(&sk, params);

            Arc::new(compute.fft(params))
        })
        .clone();

    let enc = Encryption::new(params);
    let eval = Evaluation::new(compute_key.to_owned(), &params, &enc);

    (sk, enc, eval)
}

fn ops(c: &mut Criterion) {
    let params_names = [
        (DEFAULT_128, "DEFAULT_128".to_owned()),
        (FAST_BIG_128, "FAST_BIG_128".to_owned()),
        (TURBO_CHUNGUS_128, "TURBO_CHUNGUS_128".to_owned()),
    ].into_iter().collect::<HashMap<Params, String>>();

    for p in [DEFAULT_128, FAST_BIG_128, TURBO_CHUNGUS_128] {
        let params_name = params_names.get(&p).unwrap();

        let (sk, enc, eval) = get_keys(&p);

        let sel = enc.encrypt_ggsw_l1_secret(true, &sk);
        let a = enc.encrypt_glwe_l1_secret(&Polynomial::zero(p.l1_poly_degree().0), &sk);
        let b = enc.encrypt_glwe_l1_secret(&Polynomial::zero(p.l1_poly_degree().0), &sk);

        let mut result = enc.allocate_glwe_l1();

        c.bench_function(&format!("CMux params: {params_name}"), |bench| {
            bench.iter(|| {
                eval.cmux(&mut result, &sel, &a, &b);
            });
        });

        let a = enc.encrypt_glev_l1_secret(&Polynomial::zero(p.l1_poly_degree().0), &sk);
        let b = enc.encrypt_glev_l1_secret(&Polynomial::zero(p.l1_poly_degree().0), &sk);

        let mut result = enc.allocate_glev_l1();

        c.bench_function(&format!("GLEV cmux params: {params_name}"), |bench| {
            bench.iter(|| {
                eval.glev_cmux(&mut result, &sel, &a, &b);
            });
        });

        let a = enc.encrypt_glev_l1_secret(&Polynomial::zero(p.l1_poly_degree().0), &sk);

        let mut result = enc.allocate_ggsw_l1();

        c.bench_function(&format!("Scheme switch params: {params_name}"), |bench| {
            bench.iter(|| {
                eval.scheme_switch(&mut result, &a);
            });
        });

        let a = enc.encrypt_lwe_l0_secret(false, &sk);

        let mut result = enc.allocate_ggsw_l1();

        c.bench_function(&format!("Circuit bootstrap params: {params_name}"), |bench| {
            bench.iter(|| {
                eval.circuit_bootstrap(&mut result, &a);
            });
        });

        let a = enc.encrypt_lwe_l1_secret(false, &sk);

        let mut result = enc.allocate_lwe_l0();

        c.bench_function(&format!("Keyswitch params {params_name}"), |bench| {
            bench.iter(|| {
                eval.keyswitch_lwe_l1_lwe_l0(&mut result, &a);
            });
        });
    }
}

criterion_group!(benches, ops);
criterion_main!(benches);
