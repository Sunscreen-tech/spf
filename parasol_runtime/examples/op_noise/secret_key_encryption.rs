use std::sync::Mutex;

use indicatif::ProgressBar;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sunscreen_tfhe::{
    GlweDef, GlweDimension, GlweSize, PlaintextBits, PolynomialDegree, Torus,
    entities::{GlweSecretKey, Polynomial},
    ops::polynomial::encode_polynomial,
    rand::Stddev,
};

use sunscreen_math::stats::RunningMeanVariance;

use crate::{args::SecretKeyEncryptionCommand, noise::measure_noise_glwe};

#[derive(Debug, Serialize, Deserialize)]
pub struct GlweResult {
    input_std: f64,
    output_sigma: f64,
    params: GlweDef,
}

pub fn run_secret_key_encryption(args: SecretKeyEncryptionCommand) -> GlweResult {
    let glwe = GlweDef {
        std: Stddev(args.glwe_sigma),
        dim: GlweDimension {
            size: GlweSize(args.glwe_size),
            polynomial_degree: PolynomialDegree(args.glwe_poly_degree),
        },
    };

    let msg = Polynomial::new(&(0..args.glwe_poly_degree).map(|_| 1u64).collect::<Vec<_>>());

    let mut expected = Polynomial::<Torus<u64>>::zero(args.glwe_poly_degree);
    encode_polynomial(&mut expected, &msg, PlaintextBits(1));

    let var = Mutex::new(RunningMeanVariance::new());

    let progress = ProgressBar::new(args.sample_count as u64);

    (0..args.sample_count).into_par_iter().for_each(|_| {
        let sk = GlweSecretKey::<u64>::generate_binary(&glwe);

        let ct = sk.encode_encrypt_glwe(&msg, &glwe, PlaintextBits(1));

        for s in measure_noise_glwe(&ct, &sk, &expected, &glwe, PlaintextBits(1)).unwrap() {
            var.lock().unwrap().add_sample(s);
        }

        progress.inc(1);
    });

    let std = var.lock().unwrap().std();

    GlweResult {
        input_std: args.glwe_sigma,
        output_sigma: std,
        params: glwe,
    }
}
