use std::sync::Arc;

use clap::Args;
use ndarray::{Array1, Array2};
use num::Complex;
use parasol_runtime::{
    ComputeKey, Params, SecretKey,
    metadata::{SystemInfo, print_system_info},
};
use rand::{Rng, seq::SliceRandom};
use rayon::prelude::*;
use scirs2_optimize::{Bounds, bounded_least_squares, prelude::BoundedOptions};
use serde::{Deserialize, Serialize};
use sunscreen_math::stats::RunningMeanVariance;
use sunscreen_tfhe::{
    PlaintextBits,
    entities::{GgswCiphertextFft, GlweCiphertext, Polynomial},
    high_level,
};

use crate::{
    ProbabilityAwayMeanGaussianLog, noise::measure_noise_by_keyswitch_glwe_to_lwe,
    probability_away_from_mean_gaussian_log_binary,
};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Args)]
pub struct CMuxTreeRunOptions {
    /// Number of times to run the cmux tree to measure the noise
    #[arg(long)]
    sample_count: usize,

    /// The maximum level of the cmux tree to run
    #[arg(long)]
    depth: usize,

    /// Whether to include the raw data in the output
    #[arg(long, default_value_t = false)]
    include_raw: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CMuxTreeParameters {
    pub parameter_set: Params,
    pub run_options: CMuxTreeRunOptions,
}

#[derive(Debug, Deserialize, Clone)]
pub enum Method {
    /// The method used to run the cmux tree
    RandomSelectLinesCascadedDataLines,
}

impl Method {
    pub fn description(&self) -> &'static str {
        match self {
            Method::RandomSelectLinesCascadedDataLines => {
                "The 'random select lines, cascading data lines' method generates a set of GGSW ciphertexts for each level of the CMUX tree. At every level, two GGSWs are randomly selected—one encrypting a binary value and the other its complement—and used as select lines for CMUX operations on the data lines from the previous level. The outputs from the CMUX operations become the inputs for the next level. Noise is measured by keyswitching the resulting GLWE ciphertexts at each level into the L0 LWE key. This process helps determine the maximum CMUX tree depth that can be evaluated before bootstrapping is required to keep the probability of decryption failure below a chosen threshold (e.g., 2^-64)."
            }
        }
    }
}

impl Serialize for Method {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.description())
    }
}

fn function_to_fit(x: f64, a: f64, b: f64, c: f64) -> f64 {
    a / (x + b) + c
}

#[derive(Debug, Serialize, Clone)]
pub enum FitResults {
    #[serde(rename = "results")]
    /// The fit results for the error rate
    FitErrorRate {
        /// The fit parameters: a, b, c
        a: f64,
        b: f64,
        c: f64,
        max_error: f64,
        base_2_error_at_depth_1024: f64,
    },

    #[serde(rename = "error_message")]
    /// Fit error message
    FitErrorMessage(String),
}

#[derive(Serialize, Clone)]
pub struct CMuxTreeDataFile {
    pub time: String,
    pub cmux_tree_parameters: CMuxTreeParameters,
    pub system_info: SystemInfo,
    pub method: Method,
    pub fit: FitResults,
    pub data: Vec<CMuxTreeDataPoint>,
    pub raw: Vec<Vec<Option<f64>>>,
}

#[derive(Serialize, Clone)]
struct PredictedError {
    base_10: f64,
    base_2: f64,
}

impl From<ProbabilityAwayMeanGaussianLog> for PredictedError {
    fn from(prob: ProbabilityAwayMeanGaussianLog) -> Self {
        Self {
            base_10: prob.log_10(),
            base_2: prob.log_2(),
        }
    }
}

#[derive(Serialize, Clone)]
pub struct CMuxTreeDataPoint {
    depth: usize,
    mean: f64,
    std: f64,
    predicted_err: PredictedError,
    measured_err: f64,
}

fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(!v.is_empty());
    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
    (0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| n.next().unwrap())
                .collect::<Vec<T>>()
        })
        .collect()
}

fn zero_msg(params: &Params) -> Polynomial<u64> {
    let mut msg = Polynomial::<u64>::zero(params.l1_params.dim.polynomial_degree.0);
    msg.coeffs_mut()[0] = 0u64;

    msg
}

fn one_msg(params: &Params) -> Polynomial<u64> {
    let mut msg = Polynomial::<u64>::zero(params.l1_params.dim.polynomial_degree.0);
    msg.coeffs_mut()[0] = 1u64;

    msg
}

fn trivial_zero_encryption(params: &Params) -> GlweCiphertext<u64> {
    let zero_msg = zero_msg(params);
    high_level::encryption::trivial_glwe(&zero_msg, &params.l1_params, PlaintextBits(1))
}

fn trivial_one_encryption(params: &Params) -> GlweCiphertext<u64> {
    let one_msg = one_msg(params);
    high_level::encryption::trivial_glwe(&one_msg, &params.l1_params, PlaintextBits(1))
}

fn ggsw_fft_encryption(
    val: u64,
    secret_key: &SecretKey,
    compute_key: &ComputeKey,
    params: &Params,
) -> GgswCiphertextFft<Complex<f64>> {
    let lwe0 = secret_key
        .lwe_0
        .encrypt(val, &params.l0_params, PlaintextBits(1))
        .0;

    let ggsw = high_level::evaluation::circuit_bootstrap(
        &lwe0,
        &compute_key.cbs_key,
        &compute_key.pfks_key,
        &params.l0_params,
        &params.l1_params,
        &params.l2_params,
        &params.pbs_radix,
        &params.cbs_radix,
        &params.pfks_radix,
    );

    high_level::fft::fft_ggsw(&ggsw, &params.l1_params, &params.cbs_radix)
}

#[derive(Debug, Clone, Copy)]
enum Order {
    Normal,
    Flipped,
}

/// Given two lists of GGSW ciphertexts encoding 0 and 1, this function chooses
/// a random permutation from the list of ciphertexts and a second permutation
/// with the opposite value from the first.
fn choose_permutation<T: Clone>(a: &[T], b: &[T]) -> Vec<(Order, T, T)> {
    let mut rng = rand::thread_rng();
    let mut a_permuted = a.to_vec();
    let mut b_permuted = b.to_vec();

    // We want a random arrangement before we select from each list.
    a_permuted.shuffle(&mut rng);
    b_permuted.shuffle(&mut rng);

    // Randomly swap the elements in a and b.
    a_permuted
        .into_iter()
        .zip(b_permuted)
        .map(|(a, b)| {
            if rng.gen_bool(0.5) {
                (Order::Normal, a, b)
            } else {
                (Order::Flipped, b, a)
            }
        })
        .collect()
}

fn fit_error_rate(depths: &[usize], base_2_error_rates: &[f64]) -> FitResults {
    let depths = depths.iter().map(|&d| d as f64).collect::<Vec<_>>();
    let n = depths.len();

    let residuals = |params: &[f64], y: &[f64]| {
        let a = params[0];
        let b = params[1];
        let c = params[2];

        let mut res = Array1::zeros(n);

        for (i, &x) in depths.iter().enumerate() {
            res[i] = y[i] - function_to_fit(x, a, b, c);
        }

        res
    };

    let bounds = Bounds::new(&[(None, Some(-1.0)), (None, None), (None, None)]);
    let options = BoundedOptions {
        max_iter: 10_000,
        ..Default::default()
    };

    // Initial guess for the parameters based on prior experiments.
    let initial_params = Array1::from_vec(vec![-1.6e5, 2.0e2, -3.0]);

    let data = Array1::from_vec(base_2_error_rates.to_vec());

    let results = bounded_least_squares(
        residuals,
        &initial_params,
        Some(bounds),
        None::<fn(&[f64], &[f64]) -> Array2<f64>>,
        &data,
        Some(options),
    );

    let results = results.map(|results| {
        let a = results.x[0];
        let b = results.x[1];
        let c = results.x[2];

        let max_error = depths
            .iter()
            .zip(base_2_error_rates.iter())
            .map(|(x, y)| (y - function_to_fit(*x, a, b, c)).abs() / y.abs())
            .fold(f64::NEG_INFINITY, f64::max);
        (results, max_error)
    });

    match results {
        Ok((results, max_error)) => FitResults::FitErrorRate {
            a: results.x[0],
            b: results.x[1],
            c: results.x[2],
            max_error,
            base_2_error_at_depth_1024: function_to_fit(
                1024.0,
                results.x[0],
                results.x[1],
                results.x[2],
            ),
        },
        Err(e) => FitResults::FitErrorMessage(e.to_string()),
    }
}

fn run_compute_tree(
    depth: usize,
    ones: &[Arc<GgswCiphertextFft<Complex<f64>>>],
    zeros: &[Arc<GgswCiphertextFft<Complex<f64>>>],
    secret_key: &SecretKey,
    compute_key: &ComputeKey,
    params: &Params,
) -> Vec<(crate::Result<f64>, crate::Result<f64>)> {
    let permutation = choose_permutation(ones, zeros);

    let mut a = trivial_one_encryption(params);
    let mut b = trivial_zero_encryption(params);

    let mut last_inputs = (1, 0);

    let mut samples_per_level = Vec::with_capacity(depth);

    for (order, select_1, select_2) in permutation.iter() {
        let outputs @ (out_a_expected, out_b_expected) = match order {
            Order::Normal => (last_inputs.0, last_inputs.1),
            Order::Flipped => (last_inputs.1, last_inputs.0),
        };

        // Note: select_1 = !select_2. So out_a and out_b must be different.
        let out_a =
            high_level::evaluation::cmux(select_1, &b, &a, &params.l1_params, &params.cbs_radix);

        let out_b =
            high_level::evaluation::cmux(select_2, &b, &a, &params.l1_params, &params.cbs_radix);

        // We need to measure the noise in the output ciphertexts by keyswitching eventually.
        let noise_a = measure_noise_by_keyswitch_glwe_to_lwe(
            &out_a,
            &secret_key.lwe_0,
            &compute_key.ks_key,
            out_a_expected,
            params,
            PlaintextBits(1),
        );

        let noise_b = measure_noise_by_keyswitch_glwe_to_lwe(
            &out_b,
            &secret_key.lwe_0,
            &compute_key.ks_key,
            out_b_expected,
            params,
            PlaintextBits(1),
        );

        // Concat the samples.
        samples_per_level.push((noise_a, noise_b));

        last_inputs = outputs;
        a = out_a;
        b = out_b;
    }

    samples_per_level
}

pub fn analyze_cmux_tree(cmux_tree_params: &CMuxTreeParameters) -> CMuxTreeDataFile {
    let system_info = print_system_info();

    let cmux_tree_params_pretty_json = serde_json::to_string_pretty(cmux_tree_params).unwrap();
    println!("Running with parameters:");
    println!("{}", cmux_tree_params_pretty_json);

    let run_options = cmux_tree_params.run_options;
    let params = cmux_tree_params.parameter_set.clone();
    let glwe_params = params.l1_params;

    // We will use the public key for the encryption because it might generate
    // different noise parameters.
    let secret_key = SecretKey::generate(&params);
    let compute_key = ComputeKey::generate(&secret_key, &params);

    let mut msg = Polynomial::<u64>::zero(glwe_params.dim.polynomial_degree.0);
    msg.coeffs_mut()[0] = 0u64;

    // Generate all bootstraps in parallel and in advance. This could take a lot of memory.
    println!("Generating select lines");
    let now = std::time::Instant::now();
    let zeros = (0..run_options.depth)
        .into_par_iter()
        .map(|_| Arc::new(ggsw_fft_encryption(0, &secret_key, &compute_key, &params)))
        .collect::<Vec<_>>();

    let ones = (0..run_options.depth)
        .into_par_iter()
        .map(|_| Arc::new(ggsw_fft_encryption(1, &secret_key, &compute_key, &params)))
        .collect::<Vec<_>>();
    println!("Time to generate select lines: {:?}", now.elapsed());

    println!("Running each cmux tree");
    let now = std::time::Instant::now();
    // We have a vector of size sample_count, each containing a vector of size depth of noise.
    let samples_per_run = (0..run_options.sample_count)
        .into_par_iter()
        .map(|_| {
            run_compute_tree(
                run_options.depth,
                &ones,
                &zeros,
                &secret_key,
                &compute_key,
                &params,
            )
        })
        .collect::<Vec<_>>();
    println!("Time to run cmux tree: {:?}", now.elapsed());

    // Transpose the samples, so now we have a vector of size depth, each containing a vector of size sample_count.
    let samples_per_level = transpose(samples_per_run);

    // Flatten Vec<Vec<(T, T)>> to Vec<Vec<T>>
    let samples_per_level_flattened = samples_per_level
        .iter()
        .map(|v| {
            v.iter()
                .flat_map(|(a, b)| vec![a.clone(), b.clone()])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    // Measuring noise
    let data_points_per_level = samples_per_level_flattened
        .iter()
        .enumerate()
        .map(|(i, samples_at_depth)| {
            let n_samples = samples_at_depth.len();
            let mut n_errors = 0;

            let mut rmv = RunningMeanVariance::new();

            for sample in samples_at_depth {
                if let Ok(err) = sample {
                    rmv.add_sample(*err);
                } else {
                    n_errors += 1;
                }
            }

            let std = rmv.std();
            let predicted_err = probability_away_from_mean_gaussian_log_binary(std);

            CMuxTreeDataPoint {
                mean: rmv.mean(),
                depth: i + 1,
                std,
                predicted_err: predicted_err.into(),
                measured_err: n_errors as f64 / n_samples as f64,
            }
        })
        .collect::<Vec<_>>();

    let (depths, base_2_error_rates) = data_points_per_level
        .iter()
        .map(|dp| (dp.depth, dp.predicted_err.base_2))
        .unzip::<usize, f64, Vec<_>, Vec<_>>();

    let fit = fit_error_rate(&depths, &base_2_error_rates);

    let raw = if run_options.include_raw {
        samples_per_level_flattened
            .into_iter()
            .map(|level| level.into_iter().map(|res| res.ok()).collect())
            .collect()
    } else {
        vec![]
    };

    CMuxTreeDataFile {
        time: chrono::Local::now().to_string(),
        cmux_tree_parameters: cmux_tree_params.clone(),
        system_info,
        method: Method::RandomSelectLinesCascadedDataLines,
        fit,
        data: data_points_per_level,
        raw,
    }
}
