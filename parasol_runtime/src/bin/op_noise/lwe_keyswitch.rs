use indicatif::ProgressBar;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sunscreen_math::stats::RunningMeanVariance;
use sunscreen_tfhe::{
    entities::LweSecretKey, high_level, rand::Stddev, LweDef, LweDimension, PlaintextBits,
    RadixCount, RadixDecomposition, RadixLog, Torus,
};

use crate::{args::AnalyzeLweKeyswitch, noise::measure_noise_lwe, Result};

#[derive(Debug, Serialize, Deserialize)]
pub struct LweKeyswitchAnalysisResult {
    pub in_std: f64,
    pub out_std: Result<f64>,
}

pub fn analyze_lwe_keyswitch(cmd: AnalyzeLweKeyswitch) -> Vec<LweKeyswitchAnalysisResult> {
    let from_lwe = LweDef {
        std: Stddev(cmd.from_key_sigma),
        dim: LweDimension(cmd.from_lwe_size),
    };

    let to_lwe = LweDef {
        std: Stddev(cmd.to_key_sigma),
        dim: LweDimension(cmd.to_lwe_size),
    };

    let ks_radix = RadixDecomposition {
        radix_log: RadixLog(cmd.ks_radix_log),
        count: RadixCount(cmd.ks_radix_count),
    };

    let iter_count =
        f64::log(cmd.end_sigma / cmd.start_sigma, cmd.sigma_inc).ceil() as u64 * cmd.sample_count;

    let progress = ProgressBar::new(iter_count);

    let from_sk = LweSecretKey::<u64>::generate_binary(&from_lwe);
    let to_sk = LweSecretKey::<u64>::generate_binary(&to_lwe);

    let ksk = high_level::keygen::generate_ksk(&from_sk, &to_sk, &from_lwe, &to_lwe, &ks_radix);

    let mut from_sigma = cmd.start_sigma;

    let mut results = vec![];

    while from_sigma < cmd.end_sigma {
        let enc_lwe = LweDef {
            std: Stddev(from_sigma),
            ..from_lwe
        };

        let samples = (0..cmd.sample_count)
            .into_par_iter()
            .map(|_| {
                let ct = high_level::encryption::encrypt_lwe_secret(
                    1,
                    &from_sk,
                    &enc_lwe,
                    PlaintextBits(1),
                );

                let result = high_level::evaluation::keyswitch_lwe_to_lwe(
                    &ct, &ksk, &from_lwe, &to_lwe, &ks_radix,
                );

                let samples = measure_noise_lwe(
                    &result,
                    &to_sk,
                    Torus::encode(1u64, PlaintextBits(1)),
                    &to_lwe,
                    PlaintextBits(1),
                );

                progress.inc(1);

                samples
            })
            .collect::<Result<Vec<_>>>();

        let out_std = samples.map(|s| {
            let mut var = RunningMeanVariance::new();

            s.into_iter().for_each(|x| {
                var.add_sample(x);
            });

            var.std()
        });

        results.push(LweKeyswitchAnalysisResult {
            in_std: from_sigma,
            out_std
        });

        from_sigma *= cmd.sigma_inc;
    }

    results
}
