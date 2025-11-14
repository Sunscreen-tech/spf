use indicatif::ProgressBar;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sunscreen_math::stats::RunningMeanVariance;
use sunscreen_tfhe::{
    LweDef, LweDimension, PlaintextBits, entities::LweSecretKey,
    ops::ciphertext::lwe_ciphertext_modulus_switch, rand::Stddev,
};

use crate::{Result, args::AnalyzeModulusSwitch, noise::measure_noise_lwe};

#[derive(Debug, Serialize, Deserialize)]
pub struct ModulusSwitchAnalysisSample {
    sigma_in: f64,
    sigma_out: f64,
    mean_out: f64,
}

pub fn analyze_modulus_switch(args: &AnalyzeModulusSwitch) -> Result<ModulusSwitchAnalysisSample> {
    let l0_lwe = LweDef {
        std: Stddev(args.l0_sigma),
        dim: LweDimension(args.l0_lwe_size),
    };

    let l0_sk = LweSecretKey::generate_binary(&l0_lwe);

    let progress = ProgressBar::new(args.sample_count);

    let ms_samples = (0..args.sample_count)
        .into_par_iter()
        .map(|_| {
            let mut ct0 = l0_sk.encrypt(1, &l0_lwe, PlaintextBits(1)).0;

            lwe_ciphertext_modulus_switch(&mut ct0, 0, 0, args.log_modulus, &l0_lwe);

            // "reverse" mod switch to make it decryptable
            let (c_a, c_b) = ct0.a_b_mut(&l0_lwe);
            for a in c_a {
                *a = *a << (u64::BITS - args.log_modulus) as usize;
            }
            *c_b = *c_b << (u64::BITS - args.log_modulus) as usize;

            progress.inc(1);

            measure_noise_lwe(&ct0, &l0_sk, 1, &l0_lwe, PlaintextBits(1))
        })
        .collect::<Result<Vec<_>>>();

    let mut var = RunningMeanVariance::new();

    ms_samples?.into_iter().for_each(|x| var.add_sample(x));

    Ok(ModulusSwitchAnalysisSample {
        sigma_in: args.l0_sigma,
        sigma_out: var.std(),
        mean_out: var.mean(),
    })
}
