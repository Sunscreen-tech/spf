use std::time::Instant;

use indicatif::ProgressBar;
use num::Complex;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sunscreen_math::stats::RunningMeanVariance;
use sunscreen_tfhe::{
    entities::{
        GgswCiphertext, GgswCiphertextFft, GlweSecretKey, GlweSecretKeyRef, Polynomial,
        PolynomialRef, SchemeSwitchKey, SchemeSwitchKeyFft,
    },
    high_level,
    ops::{
        bootstrapping::{generate_scheme_switch_key, scheme_switch},
        fft_ops::scheme_switch_fft,
    },
    rand::Stddev,
    GlweDef, GlweDimension, GlweSize, PolynomialDegree, RadixCount, RadixDecomposition, RadixLog,
};

use crate::{
    args::{AnalyzeSchemeSwitch, SearchSchemeSwitchCommand},
    noise::measure_noise_ggsw,
    Error, Result,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct SchemeSwitchSample {
    ss_radix_log: usize,
    ss_radix_count: usize,
    in_std: f64,
    out_std: f64,
    time: f64,
    error: Option<Error>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SchemeSwitchResult {
    Ok(SchemeSwitchSample),
    Err {
        ss_radix_log: usize,
        ss_radix_count: usize,
        err: Error,
    },
}

pub fn search_scheme_switch(args: &SearchSchemeSwitchCommand) -> Vec<SchemeSwitchResult> {
    let glwe = GlweDef {
        std: Stddev(args.key_sigma),
        dim: GlweDimension {
            size: GlweSize(args.glwe_size),
            polynomial_degree: PolynomialDegree(args.glwe_poly_degree),
        },
    };

    let cbs_radix = RadixDecomposition {
        radix_log: RadixLog(args.cbs_radix_log),
        count: RadixCount(args.cbs_radix_count),
    };

    let sk = high_level::keygen::generate_binary_glwe_sk(&glwe);

    let num_iters = args.max_count - args.min_count + 1;
    let num_iters = (args.max_decomp - args.min_decomp + 1) * num_iters;

    let progress = ProgressBar::new(args.sample_count * num_iters as u64);

    let mut msg = Polynomial::zero(args.glwe_poly_degree);
    msg.coeffs_mut()[0] = 1;

    let mut samples = vec![];

    for ss_radix_count in args.min_count..=args.max_count {
        for ss_radix_log in args.min_radix_log..=args.max_radix_log {
            let decomp_size = ss_radix_log * ss_radix_count;

            if decomp_size > args.max_decomp || decomp_size < args.min_decomp {
                progress.inc(args.sample_count);
                continue;
            }

            let result = evaluate_params(
                args,
                &msg,
                &sk,
                &glwe,
                ss_radix_log,
                ss_radix_count,
                &cbs_radix,
                &progress,
            );

            samples.push(match result {
                Ok(v) => SchemeSwitchResult::Ok(v),
                Err(err) => SchemeSwitchResult::Err {
                    ss_radix_log,
                    ss_radix_count,
                    err,
                },
            });
        }
    }

    samples
}

fn evaluate_params(
    args: &SearchSchemeSwitchCommand,
    msg: &PolynomialRef<u64>,
    sk: &GlweSecretKeyRef<u64>,
    glwe: &GlweDef,
    ss_radix_log: usize,
    ss_radix_count: usize,
    cbs_radix: &RadixDecomposition,
    progress: &ProgressBar,
) -> Result<SchemeSwitchSample> {
    let ss_radix = RadixDecomposition {
        radix_log: RadixLog(ss_radix_log),
        count: RadixCount(ss_radix_count),
    };

    let mut ss_key = SchemeSwitchKey::<u64>::new(glwe, &ss_radix);
    generate_scheme_switch_key(&mut ss_key, sk, glwe, &ss_radix);

    let ss_key_fft = if !args.ntt {
        let mut ss_key_fft = SchemeSwitchKeyFft::<Complex<f64>>::new(glwe, &ss_radix);
        ss_key.fft(&mut ss_key_fft, glwe, &ss_radix);

        Some(ss_key_fft)
    } else {
        None
    };

    let noise = (0..args.sample_count)
        .into_par_iter()
        .map(|_| {
            let mut output = GgswCiphertext::new(glwe, cbs_radix);
            let mut output_fft = GgswCiphertextFft::new(glwe, cbs_radix);

            let encryption_params = GlweDef {
                std: Stddev(args.input_sigma),
                ..glwe.to_owned()
            };

            let ct = high_level::encryption::encrypt_binary_msg_secret_glev(
                msg,
                sk,
                &encryption_params,
                cbs_radix,
            );

            let now = Instant::now();

            if args.ntt {
                scheme_switch(&mut output, &ct, &ss_key, glwe, cbs_radix, &ss_radix);
            } else {
                scheme_switch_fft(
                    &mut output_fft,
                    &ct,
                    ss_key_fft.as_ref().unwrap(),
                    glwe,
                    cbs_radix,
                    &ss_radix,
                );
            }
            let time = now.elapsed().as_secs_f64();

            if !args.ntt {
                output_fft.ifft(&mut output, glwe, cbs_radix);
            }

            let noise = measure_noise_ggsw(&output, sk, true, glwe, cbs_radix);

            progress.inc(1);

            (noise, time)
        })
        .collect::<Vec<_>>();

    let mut err_var = RunningMeanVariance::new();
    let mut time_var = RunningMeanVariance::new();

    for (noise, time) in noise.into_iter() {
        for x in noise? {
            err_var.add_sample(x);
        }

        time_var.add_sample(time);
    }

    Ok(SchemeSwitchSample {
        in_std: args.input_sigma,
        out_std: err_var.std(),
        ss_radix_count,
        ss_radix_log,
        time: time_var.mean(),
        error: None,
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SchemeSwitchAnalysisSample {
    sigma_in: f64,
    sigma_out: f64,
}

pub fn analyze_scheme_switch(args: &AnalyzeSchemeSwitch) -> Vec<SchemeSwitchAnalysisSample> {
    let glwe = GlweDef {
        std: Stddev(args.sigma),
        dim: GlweDimension {
            size: GlweSize(args.glwe_size),
            polynomial_degree: PolynomialDegree(args.glwe_poly_degree),
        },
    };

    let ss_radix = RadixDecomposition {
        radix_log: RadixLog(args.ss_radix_log),
        count: RadixCount(args.ss_radix_count),
    };

    let cbs_radix = RadixDecomposition {
        radix_log: RadixLog(args.cbs_radix_log),
        count: RadixCount(args.cbs_radix_count),
    };

    let count = f64::log(args.end_sigma / args.sigma, args.step).ceil() as usize;

    let progress = ProgressBar::new((args.sample_count * count) as u64);

    let mut cur_sigma = args.sigma;

    let sk = GlweSecretKey::<u64>::generate_binary(&glwe);

    let mut ssk = SchemeSwitchKey::new(&glwe, &ss_radix);

    generate_scheme_switch_key(&mut ssk, &sk, &glwe, &ss_radix);

    let mut ssk_fft = SchemeSwitchKeyFft::new(&glwe, &ss_radix);

    ssk.fft(&mut ssk_fft, &glwe, &ss_radix);

    let mut msg = Polynomial::zero(args.glwe_poly_degree);
    msg.coeffs_mut()[0] = 1;

    let mut samples = vec![];

    while cur_sigma < args.end_sigma {
        let noise = (0..args.sample_count)
            .into_par_iter()
            .map(|_| {
                let encryption_glwe = GlweDef {
                    std: Stddev(cur_sigma),
                    ..glwe.to_owned()
                };

                let ct = high_level::encryption::encrypt_binary_msg_secret_glev(
                    &msg,
                    &sk,
                    &encryption_glwe,
                    &cbs_radix,
                );

                progress.inc(1);

                let mut output = GgswCiphertext::new(&encryption_glwe, &cbs_radix);
                let mut output_fft = GgswCiphertextFft::new(&encryption_glwe, &cbs_radix);

                if args.ntt {
                    scheme_switch(
                        &mut output,
                        &ct,
                        &ssk,
                        &encryption_glwe,
                        &cbs_radix,
                        &ss_radix,
                    );
                } else {
                    scheme_switch_fft(
                        &mut output_fft,
                        &ct,
                        &ssk_fft,
                        &encryption_glwe,
                        &cbs_radix,
                        &ss_radix,
                    );
                    output_fft.ifft(&mut output, &encryption_glwe, &cbs_radix);
                }

                measure_noise_ggsw(&output, &sk, true, &glwe, &cbs_radix)
            })
            .collect::<Result<Vec<_>>>();

        let mut var = RunningMeanVariance::new();

        match noise {
            Ok(val) => val.into_iter().flatten().collect::<Vec<_>>(),
            Err(_) => {
                println!("Decryption error. Stopping.");
                break;
            }
        }
        .iter()
        .for_each(|x| var.add_sample(*x));

        samples.push(SchemeSwitchAnalysisSample {
            sigma_in: cur_sigma,
            sigma_out: var.std(),
        });

        cur_sigma *= args.step;
    }

    samples
}
