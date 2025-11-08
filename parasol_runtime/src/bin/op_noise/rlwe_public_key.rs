use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sunscreen_math::stats::RunningMeanVariance;
use sunscreen_tfhe::{
    entities::{GlweCiphertext, GlweSecretKey, Polynomial},
    high_level,
    ops::{encryption::rlwe_encode_encrypt_public, polynomial::encode_polynomial},
    rand::Stddev,
    GlweDef, GlweDimension, GlweSize, PlaintextBits, PolynomialDegree,
};

use crate::Result;
use crate::{args::AnalyzeRlwePublicKeyEncryption, noise::measure_noise_glwe};

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyAnalysisResult {
    pub input_std: f64,
    pub out_std: f64,
}

pub fn analyze_rlwe_public_key_encryption(
    cmd: AnalyzeRlwePublicKeyEncryption,
) -> Result<PublicKeyAnalysisResult> {
    let glwe = GlweDef {
        std: Stddev(cmd.key_sigma),
        dim: GlweDimension {
            size: GlweSize(cmd.glwe_size),
            polynomial_degree: PolynomialDegree(cmd.glwe_poly_degree),
        },
    };

    let mut msg = Polynomial::<u64>::zero(cmd.glwe_poly_degree);
    msg.as_mut_slice()[0] = 1;
    let mut expected = Polynomial::zero(cmd.glwe_poly_degree);

    encode_polynomial(&mut expected, &msg, PlaintextBits(1));

    let samples = (0..cmd.sample_count)
        .into_par_iter()
        .map(|x| {
            let sk = high_level::keygen::generate_binary_glwe_sk(&glwe);
            let pk = high_level::keygen::generate_rlwe_public_key(&sk, &glwe);

            let mut ct = GlweCiphertext::new(&glwe);

            rlwe_encode_encrypt_public(&mut ct, &msg, &pk, &PlaintextBits(1), &glwe);

            measure_noise_glwe(&ct, &sk, &expected, &glwe, PlaintextBits(1))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut var = RunningMeanVariance::new();

    samples
        .into_iter()
        .flatten()
        .for_each(|x| var.add_sample(x));

    Ok(PublicKeyAnalysisResult {
        input_std: cmd.key_sigma,
        out_std: var.std(),
    })
}
