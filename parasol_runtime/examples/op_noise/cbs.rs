use indicatif::ProgressBar;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sunscreen_math::stats::RunningMeanVariance;
use sunscreen_tfhe::{
    GlweDef, GlweDimension, GlweSize, LweDef, LweDimension, PlaintextBits, PolynomialDegree,
    RadixCount, RadixDecomposition, RadixLog,
    entities::{GlweSecretKey, LweSecretKey},
    high_level::{self, keygen},
    rand::Stddev,
};

use crate::Result;
use crate::{args::AnalyzeCbs, noise::measure_noise_ggsw};

#[derive(Serialize, Deserialize)]
pub struct CbsSample {
    pub in_sigma: f64,
    pub out_sigma: f64,
}

pub fn analyze_cbs(cbs: &AnalyzeCbs) -> Result<CbsSample> {
    let l0_lwe = LweDef {
        std: Stddev(cbs.l0_sigma),
        dim: LweDimension(cbs.l0_lwe_size),
    };

    let l1_glwe = GlweDef {
        std: Stddev(cbs.l1_sigma),
        dim: GlweDimension {
            size: GlweSize(cbs.l1_glwe_size),
            polynomial_degree: PolynomialDegree(cbs.l1_glwe_poly_degree),
        },
    };

    let l2_glwe = GlweDef {
        std: Stddev(cbs.l2_sigma),
        dim: GlweDimension {
            size: GlweSize(cbs.l2_glwe_size),
            polynomial_degree: PolynomialDegree(cbs.l2_glwe_poly_degree),
        },
    };

    let cbs_radix = RadixDecomposition {
        radix_log: RadixLog(cbs.cbs_radix_log),
        count: RadixCount(cbs.cbs_radix_count),
    };

    let pbs_radix = RadixDecomposition {
        radix_log: RadixLog(cbs.pbs_radix_log),
        count: RadixCount(cbs.pbs_radix_count),
    };

    let pfks_radix = RadixDecomposition {
        radix_log: RadixLog(cbs.pfks_radix_log),
        count: RadixCount(cbs.pfks_radix_count),
    };

    let l0_sk = LweSecretKey::<u64>::generate_binary(&l0_lwe);
    let l1_sk = GlweSecretKey::<u64>::generate_binary(&l1_glwe);
    let l2_sk = GlweSecretKey::<u64>::generate_binary(&l2_glwe);

    let pfks_key = keygen::generate_cbs_ksk(
        l2_sk.to_lwe_secret_key(),
        &l1_sk,
        &l2_glwe.as_lwe_def(),
        &l1_glwe,
        &pfks_radix,
    );

    let pbs_key = keygen::generate_bootstrapping_key(&l0_sk, &l2_sk, &l0_lwe, &l2_glwe, &pbs_radix);

    let pbs_key = high_level::fft::fft_bootstrap_key(&pbs_key, &l0_lwe, &l2_glwe, &pbs_radix);

    let progress = ProgressBar::new(cbs.sample_count);

    let cbs_samples = (0..cbs.sample_count)
        .into_par_iter()
        .map(|_| {
            let encryption_params = LweDef {
                std: Stddev(cbs.l0_sigma),
                ..l0_lwe
            };

            let ct0 = l0_sk.encrypt(1, &encryption_params, PlaintextBits(1)).0;

            let ggsw = high_level::evaluation::circuit_bootstrap(
                &ct0,
                &pbs_key,
                &pfks_key,
                &l0_lwe,
                &l1_glwe,
                &l2_glwe,
                &pbs_radix,
                &cbs_radix,
                &pfks_radix,
            );

            let noise = measure_noise_ggsw(&ggsw, &l1_sk, true, &l1_glwe, &cbs_radix);

            progress.inc(1);

            noise
        })
        .collect::<Result<Vec<_>>>();

    let mut var = RunningMeanVariance::new();

    cbs_samples?
        .into_iter()
        .flatten()
        .for_each(|x| var.add_sample(x));

    Ok(CbsSample {
        in_sigma: cbs.l0_sigma,
        out_sigma: var.std(),
    })
}
