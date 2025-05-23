use indicatif::ProgressBar;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sunscreen_math::stats::RunningMeanVariance;
use sunscreen_tfhe::{
    GlweDef, GlweDimension, GlweSize, PlaintextBits, PolynomialDegree, RadixCount,
    RadixDecomposition, RadixLog,
    entities::{GgswCiphertextRef, GlweCiphertext, GlweCiphertextRef, GlweSecretKey, Polynomial},
    high_level::{self},
    ops::{
        ciphertext::{glwe_ggsw_mad, sub_glwe_ciphertexts},
        polynomial::encode_polynomial,
    },
    rand::Stddev,
};

use crate::{
    Result, args::AnalyzeCMux, noise::measure_noise_glwe,
    probability_away_from_mean_gaussian_log_binary,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct CMuxSample {
    pub ggsw_sigma: f64,
    pub a_sigma: f64,
    pub b_sigma: f64,
    pub out_sigma: f64,
    pub out_error_rate_base_10_log: f64,
    pub out_error_rate_base_2_log: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CMuxRun {
    pub cmux_samples: Vec<CMuxSample>,
    pub parameters: AnalyzeCMux,
}

pub fn analyze_cmux(cmd: &AnalyzeCMux) -> Vec<CMuxSample> {
    println!("Running with the following parameters:");
    println!("{}", serde_json::to_string_pretty(cmd).unwrap());

    let glwe = GlweDef {
        std: Stddev(cmd.key_sigma),
        dim: GlweDimension {
            size: GlweSize(cmd.glwe_size),
            polynomial_degree: PolynomialDegree(cmd.glwe_poly_degree),
        },
    };

    let cbs_radix = RadixDecomposition {
        radix_log: RadixLog(cmd.cbs_radix_log),
        count: RadixCount(cmd.cbs_radix_count),
    };

    let sk = GlweSecretKey::<u64>::generate_binary(&glwe);

    let mut ggsw_sigma = cmd.start_sigma;

    let iter_count = f64::log(cmd.end_sigma / cmd.start_sigma, cmd.sigma_inc).ceil() as u64;
    let progress_ticks = iter_count * (iter_count + 1) * cmd.sample_count;

    let progress = ProgressBar::new(progress_ticks);

    let mut msg = Polynomial::<u64>::zero(cmd.glwe_poly_degree);
    msg.coeffs_mut()[0] = 0u64;

    let mut expected = Polynomial::zero(cmd.glwe_poly_degree);
    encode_polynomial(&mut expected, &msg, PlaintextBits(1));

    let mut noise_results = vec![];

    // Trivial a and b ciphertexts are interesting, so we'll special case them.
    let mut a_sigma = 0.0;

    for _ in 0..iter_count {
        let mut b_sigma: f64 = 0.0;

        let ggsw_enc_params = GlweDef {
            std: Stddev(ggsw_sigma),
            ..glwe
        };

        for _ in 0..iter_count + 1 {
            let a_enc_params = GlweDef {
                std: Stddev(a_sigma),
                ..glwe
            };

            // The resulting error is affected by the max error of a and b (within a small additive term so we just vary and collect a to make the analysis much faster.
            let b_enc_params = GlweDef {
                std: Stddev(b_sigma),
                ..glwe
            };

            let samples = (0..cmd.sample_count)
                .into_par_iter()
                .map(|_| {
                    let sel = high_level::encryption::encrypt_ggsw(
                        1,
                        &sk,
                        &ggsw_enc_params,
                        &cbs_radix,
                        PlaintextBits(1),
                    );
                    let sel_fft = high_level::fft::fft_ggsw(&sel, &ggsw_enc_params, &cbs_radix);

                    let a = high_level::encryption::encrypt_glwe(
                        &msg,
                        &sk,
                        &a_enc_params,
                        PlaintextBits(1),
                    );
                    let b = high_level::encryption::encrypt_glwe(
                        &msg,
                        &sk,
                        &b_enc_params,
                        PlaintextBits(1),
                    );

                    let res = if cmd.ntt {
                        cmux_ntt(&sel, &a, &b, &glwe, &cbs_radix)
                    } else {
                        high_level::evaluation::cmux(&sel_fft, &a, &b, &glwe, &cbs_radix)
                    };

                    let samples = measure_noise_glwe(&res, &sk, &expected, &glwe, PlaintextBits(1));

                    progress.inc(1);

                    samples
                })
                .collect::<Result<Vec<_>>>();

            let std = samples.map(|x| {
                let mut var = RunningMeanVariance::new();

                x.into_iter().flatten().for_each(|x| {
                    var.add_sample(x);
                });

                var.std()
            });

            let std = match std {
                Ok(std) => std,
                Err(e) => {
                    eprintln!("Error measuring noise: {:?}", e);
                    continue;
                }
            };

            let error_rate = probability_away_from_mean_gaussian_log_binary(std);

            noise_results.push(CMuxSample {
                ggsw_sigma,
                a_sigma,
                b_sigma,
                out_sigma: std,
                out_error_rate_base_10_log: error_rate.log_10(),
                out_error_rate_base_2_log: error_rate.log_2(),
            });

            b_sigma = next_sigma(b_sigma, cmd.start_sigma, cmd.sigma_inc);
            a_sigma = next_sigma(a_sigma, cmd.start_sigma, cmd.sigma_inc);
        }

        ggsw_sigma = next_sigma(ggsw_sigma, cmd.start_sigma, cmd.sigma_inc);
    }

    noise_results
}

fn next_sigma(cur: f64, start: f64, inc: f64) -> f64 {
    assert_ne!(start, 0.0);

    if cur == 0.0 { start } else { cur * inc }
}

fn cmux_ntt(
    sel: &GgswCiphertextRef<u64>,
    a: &GlweCiphertextRef<u64>,
    b: &GlweCiphertextRef<u64>,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
) -> GlweCiphertext<u64> {
    let mut c = a.to_owned();
    let mut b_min_a = GlweCiphertext::new(glwe);

    sub_glwe_ciphertexts(&mut b_min_a, b, a, glwe);

    glwe_ggsw_mad(&mut c, &b_min_a, sel, glwe, radix);

    c
}
