use indicatif::ProgressBar;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sunscreen_math::stats::RunningMeanVariance;
use sunscreen_tfhe::{
    LweDef, LweDimension, PlaintextBits, RadixCount, RadixDecomposition, RadixLog,
    entities::{LweCiphertext, LweSecretKey},
    high_level, ops,
    rand::Stddev,
};

use crate::{Result, args::AnalyzeMeanCompRadixDecomp, noise::measure_noise_lwe};

#[derive(Debug, Serialize, Deserialize)]
pub struct MeanCompRadixDecompAnalysisResult {
    pub in_std: f64,
    pub out_std_with_mc: f64,
    pub out_mean_with_mc: f64,
    pub out_std_without_mc: f64,
    pub out_mean_without_mc: f64,
}

pub fn analyze_mean_compensation_radix_decomposition(
    cmd: &AnalyzeMeanCompRadixDecomp,
) -> Result<MeanCompRadixDecompAnalysisResult> {
    let l0_lwe = LweDef {
        std: Stddev(cmd.l0_sigma),
        dim: LweDimension(cmd.l0_lwe_size),
    };

    let l0_sk = LweSecretKey::<u64>::generate_binary(&l0_lwe);

    let ks_radix = RadixDecomposition {
        radix_log: RadixLog(cmd.ks_radix_log),
        count: RadixCount(cmd.ks_radix_count),
    };

    let progress = ProgressBar::new(cmd.sample_count);

    let (samples_with_mean_comp, samples_without_mean_comp) = (0..cmd.sample_count)
        .into_par_iter()
        .map(|_| {
            let ct =
                high_level::encryption::encrypt_lwe_secret(1, &l0_sk, &l0_lwe, PlaintextBits(1));

            let mut out = LweCiphertext::zero(&l0_lwe);

            ops::keyswitch::lwe_keyswitch::mean_compensate_pre_keyswitch_lwe_to_lwe(
                &mut out, &ct, &l0_lwe, &ks_radix,
            );

            let noise_with_mean_comp =
                measure_noise_lwe(&out, &l0_sk, 1, &l0_lwe, PlaintextBits(1));

            // restores original B to measure the noise without mean compensation
            *out.b_mut(&l0_lwe) = *ct.b(&l0_lwe);

            let noise_without_mean_comp =
                measure_noise_lwe(&out, &l0_sk, 1, &l0_lwe, PlaintextBits(1));

            progress.inc(1);

            (noise_with_mean_comp, noise_without_mean_comp)
        })
        .collect::<(Result<Vec<_>>, Result<Vec<_>>)>();

    let mut var_with_mean_comp = RunningMeanVariance::new();
    let mut var_without_mean_comp = RunningMeanVariance::new();

    samples_with_mean_comp?.into_iter().for_each(|x| {
        var_with_mean_comp.add_sample(x);
    });
    samples_without_mean_comp?.into_iter().for_each(|x| {
        var_without_mean_comp.add_sample(x);
    });

    Ok(MeanCompRadixDecompAnalysisResult {
        in_std: cmd.l0_sigma,
        out_std_with_mc: var_with_mean_comp.std(),
        out_mean_with_mc: var_with_mean_comp.mean(),
        out_std_without_mc: var_without_mean_comp.std(),
        out_mean_without_mc: var_without_mean_comp.mean(),
    })
}
