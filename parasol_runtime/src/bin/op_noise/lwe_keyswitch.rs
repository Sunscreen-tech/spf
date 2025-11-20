use indicatif::ProgressBar;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sunscreen_math::stats::RunningMeanVariance;
use sunscreen_tfhe::{
    LweDef, LweDimension, PlaintextBits, RadixCount, RadixDecomposition, RadixLog,
    entities::LweSecretKey, high_level, rand::Stddev,
};

use crate::{Result, args::AnalyzeLweKeyswitch, noise::measure_noise_lwe};

#[derive(Debug, Serialize, Deserialize)]
pub struct LweKeyswitchAnalysisResult {
    pub in_std: f64,
    pub out_std: f64,
    pub out_mean: f64,
}

pub fn analyze_lwe_keyswitch(cmd: &AnalyzeLweKeyswitch) -> Result<LweKeyswitchAnalysisResult> {
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

    let progress = ProgressBar::new(cmd.sample_count);

    let from_sk = LweSecretKey::<u64>::generate_binary(&from_lwe);
    let to_sk = LweSecretKey::<u64>::generate_binary(&to_lwe);

    let ksk = high_level::keygen::generate_ksk(&from_sk, &to_sk, &from_lwe, &to_lwe, &ks_radix);

    let samples = (0..cmd.sample_count)
        .into_par_iter()
        .map(|_| {
            let ct_lwe = LweDef {
                std: Stddev(cmd.input_sigma),
                ..from_lwe
            };

            let ct =
                high_level::encryption::encrypt_lwe_secret(1, &from_sk, &ct_lwe, PlaintextBits(1));

            let result = high_level::evaluation::keyswitch_lwe_to_lwe(
                &ct, &ksk, &from_lwe, &to_lwe, &ks_radix,
            );

            progress.inc(1);
            measure_noise_lwe(&result, &to_sk, 1, &to_lwe, PlaintextBits(1))
        })
        .collect::<Result<Vec<_>>>();

    let mut var = RunningMeanVariance::new();

    samples?.into_iter().for_each(|x| var.add_sample(x));

    Ok(LweKeyswitchAnalysisResult {
        in_std: cmd.from_key_sigma,
        out_std: var.std(),
        out_mean: var.mean(),
    })
}
