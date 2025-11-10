use crate::Result;
use crate::{args::AnalyzePbs, noise::measure_noise_glwe};
use indicatif::ProgressBar;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sunscreen_math::stats::RunningMeanVariance;
use sunscreen_tfhe::{
    AddendCount, GlweDef, GlweDimension, GlweSize, LweDef, LweDimension, PlaintextBits,
    PolynomialDegree, RadixCount, RadixDecomposition, RadixLog,
    entities::{GlweCiphertext, GlweSecretKey, LweSecretKey, Polynomial, UnivariateLookupTable},
    high_level::{self, keygen},
    ops::bootstrapping::generalized_programmable_bootstrap,
    rand::Stddev,
};

#[derive(Serialize, Deserialize)]
pub struct PbsSample {
    pub in_sigma: f64,
    pub out_sigma: f64,
}

pub fn analyze_pbs(pbs: &AnalyzePbs) -> Result<PbsSample> {
    let l0_lwe = LweDef {
        std: Stddev(pbs.l0_sigma),
        dim: LweDimension(pbs.l0_lwe_size),
    };

    let l1_glwe = GlweDef {
        std: Stddev(pbs.l1_sigma),
        dim: GlweDimension {
            size: GlweSize(pbs.l1_glwe_size),
            polynomial_degree: PolynomialDegree(pbs.l1_glwe_poly_degree),
        },
    };

    let pbs_radix = RadixDecomposition {
        radix_log: RadixLog(pbs.pbs_radix_log),
        count: RadixCount(pbs.pbs_radix_count),
    };

    let addend_count = AddendCount(pbs.addend_count);

    let l0_sk = LweSecretKey::<u64>::generate_binary(&l0_lwe);
    let l1_sk = GlweSecretKey::<u64>::generate_binary(&l1_glwe);

    let pbs_key = keygen::generate_bootstrapping_key(
        &l0_sk,
        &l1_sk,
        &l0_lwe,
        &l1_glwe,
        &pbs_radix,
        addend_count,
    );

    let pbs_key =
        high_level::fft::fft_bootstrap_key(&pbs_key, &l0_lwe, &l1_glwe, &pbs_radix, addend_count);

    let progress = ProgressBar::new(pbs.sample_count);

    let pbs_samples = (0..pbs.sample_count)
        .into_par_iter()
        .map(|_| {
            let encryption_params = LweDef {
                std: Stddev(pbs.l0_sigma),
                ..l0_lwe
            };

            let ct0 = l0_sk.encrypt(1, &encryption_params, PlaintextBits(1)).0;

            let mut out: GlweCiphertext<u64> = GlweCiphertext::new(&l1_glwe);
            let lut = UnivariateLookupTable::trivial_from_fn(
                |idx| {
                    let qrt = l1_glwe.dim.polynomial_degree.0 as u64 / 4;
                    if idx >= qrt && idx <= qrt * 3 { 1 } else { 0 }
                },
                &l1_glwe,
                PlaintextBits(1),
            );
            generalized_programmable_bootstrap(
                &mut out,
                &ct0,
                &lut,
                &pbs_key,
                0,
                0,
                &l0_lwe,
                &l1_glwe,
                &pbs_radix,
                addend_count,
            );

            let noise = measure_noise_glwe(
                &out,
                &l1_sk,
                {
                    let mut poly = Polynomial::zero(l1_glwe.dim.polynomial_degree.0);
                    poly.coeffs_mut()[0] = 1;
                    poly
                }
                .as_torus(),
                &l1_glwe,
                PlaintextBits(1),
            );

            progress.inc(1);

            noise
        })
        .collect::<Result<Vec<_>>>();

    let mut var = RunningMeanVariance::new();

    pbs_samples?
        .into_iter()
        .flatten()
        .for_each(|x| var.add_sample(x));

    Ok(PbsSample {
        in_sigma: pbs.l0_sigma,
        out_sigma: var.std(),
    })
}
