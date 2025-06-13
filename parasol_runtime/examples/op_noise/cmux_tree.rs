use std::sync::Arc;

use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use ndarray::{Array1, Array2};
use num::Complex;
use parasol_runtime::{
    ComputeKey, Params, SecretKey,
    metadata::{SystemInfo, get_system_info, print_system_info},
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
    probability_away_from_mean_gaussian_log, probability_away_from_mean_gaussian_log_binary,
};

const PROGRESS_BAR_TEMPLATE: &str = "{wide_bar} Items {pos:>4}/{len:4} Elapsed {elapsed_precise} ETA {eta_precise} Est Duration {duration_precise}";

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Args)]
pub struct CMuxTreeRunOptions {
    /// Number of times to run the cmux tree to measure the noise in the drift.
    #[arg(long)]
    drift_sample_count: usize,

    /// The maximum level of the cmux tree to run when estimating the drift.
    #[arg(long)]
    drift_depth: usize,

    /// The maximum level of the cmux tree to run when estimating the change in
    /// the standard deviation
    #[arg(long)]
    std_depth: usize,

    /// Number of times to run the cmux tree to measure the noise in the
    /// standard deviation
    #[arg(long)]
    std_sample_count: usize,

    /// Whether to include the raw data in the output
    #[arg(long, default_value_t = false)]
    include_raw: bool,

    /// How many standard deviations away from the mean drift to assume for the
    /// worst case when performing the error fit.
    #[arg(long, default_value_t = 3.0)]
    simulated_drift: f64,

    /// How many standard deviations away from the mean drift offset to
    /// assume for the worst case when performing the error fit.
    #[arg(long, default_value_t = 3.0)]
    simulated_drift_offset: f64,
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
    RandomSelectLinesCascadedDataLinesWithDrift,
}

impl Method {
    pub fn description(&self) -> &'static str {
        match self {
            Method::RandomSelectLinesCascadedDataLines => {
                "The 'random select lines, cascading data lines' method generates a set of GGSW ciphertexts for each level of the CMUX tree. At every level, two GGSWs are randomly selected—one encrypting a binary value and the other its complement—and used as select lines for CMUX operations on the data lines from the previous level. The outputs from the CMUX operations become the inputs for the next level. Noise is measured by keyswitching the resulting GLWE ciphertexts at each level into the L0 LWE key. This process helps determine the maximum CMUX tree depth that can be evaluated before bootstrapping is required to keep the probability of decryption failure below a chosen threshold (e.g., 2^-64)."
            }
            Method::RandomSelectLinesCascadedDataLinesWithDrift => {
                "The 'random select lines, cascading data lines' method generates a set of GGSW ciphertexts for each level of the CMUX tree. At every level, two GGSWs are randomly selected—one encrypting a binary value and the other its complement—and used as select lines for CMUX operations on the data lines from the previous level. The outputs from the CMUX operations become the inputs for the next level. Noise is measured by keyswitching the resulting GLWE ciphertexts at each level into the L0 LWE key. In addition, the drift in the encoded position on the torus is calculated after each CMUX operation, which helps in understanding how the encoding drifts with each operation. Both the changes in the standard deviation and the drift helps determine the maximum CMUX tree depth that can be evaluated before bootstrapping is required to keep the probability of decryption failure below a chosen threshold (e.g., 2^-64)."
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
    -1.0 / (a * (x + b)) + c
}

const FUNCTION_TO_FIT_DESCRIPTION: &str = "f(x) = -1 / (a * (x + b)) + c";

#[derive(Debug, Serialize, Clone)]
pub enum FitResults {
    #[serde(rename = "results")]
    /// The fit results for the error rate
    FitErrorRate {
        /// The fit parameters: a, b, c
        a: f64,
        b: f64,
        c: f64,
        equation: String,
        max_error: f64,
        base_2_error_at_depth_256: f64,
    },

    #[serde(rename = "error_message")]
    /// Fit error message
    FitErrorMessage(String),
}

#[derive(Serialize, Clone)]
pub struct CMuxTreeDataFile {
    pub version: u32,
    pub time: String,
    pub cmux_tree_parameters: CMuxTreeParameters,
    pub system_info: SystemInfo,
    pub method: Method,
    pub fit: FitResults,
    pub drift_data: Vec<CMuxTreeDriftDataPoint>,
    pub drift_raw: Vec<Vec<(Option<f64>, Option<f64>)>>,
    pub std_data: Vec<CMuxTreeStdDataPoint>,
    pub std_raw: Vec<Vec<Option<f64>>>,
}

impl CMuxTreeDataFile {
    pub fn new(
        cmux_tree_parameters: CMuxTreeParameters,
        fit: FitResults,
        drift_data: Vec<CMuxTreeDriftDataPoint>,
        drift_raw: Vec<Vec<(Option<f64>, Option<f64>)>>,
        std_data: Vec<CMuxTreeStdDataPoint>,
        std_raw: Vec<Vec<Option<f64>>>,
    ) -> Self {
        Self {
            version: 1,
            time: chrono::Local::now().to_string(),
            cmux_tree_parameters,
            system_info: get_system_info(),
            method: Method::RandomSelectLinesCascadedDataLinesWithDrift,
            fit,
            drift_data,
            drift_raw,
            std_data,
            std_raw,
        }
    }
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

/// The linear fit to the drift of the CMUX tree.
#[derive(Serialize, Clone)]
pub struct CMuxTreeDriftDataPoint {
    /// Drift in the encoded position on the torus after performing the CMUX
    /// operation. Units is normalized torus unit per CMUX operation (depth);
    /// otherwise said, how much the encoding drifts after each CMUX operation.
    drift: f64,

    /// Offset of the drift; ideally should be close to zero.
    offset: f64,

    /// Max error in the calculated drift, calculated as the largest error in a
    /// given data point versus the maximum value of the drift.
    max_error: f64,
}

#[derive(Serialize, Clone)]
pub struct CMuxTreeStdDataPoint {
    depth: usize,
    mean: f64,
    std: f64,
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

    high_level::evaluation::circuit_bootstrap(
        &lwe0,
        &compute_key.bs_key,
        &compute_key.auto_key,
        &compute_key.ss_key,
        &params.l0_params,
        &params.l1_params,
        &params.pbs_radix,
        &params.tr_radix,
        &params.ss_radix,
        &params.cbs_radix,
    )
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

fn linear_regression(xs: &[f64], ys: &[f64]) -> (f64, f64, f64) {
    if xs.len() != ys.len() || xs.is_empty() {
        panic!("Input vectors must have the same non-zero length");
    }

    let n = xs.len() as f64;
    let sum_x: f64 = xs.iter().sum();
    let sum_y: f64 = ys.iter().sum();
    let sum_xx: f64 = xs.iter().map(|x| x * x).sum();
    let sum_xy: f64 = xs.iter().zip(ys.iter()).map(|(x, y)| x * y).sum();

    let denominator = n * sum_xx - sum_x * sum_x;
    if denominator == 0.0 {
        return (f64::NAN, f64::NAN, f64::NAN);
    }

    let slope = (n * sum_xy - sum_x * sum_y) / denominator;
    let intercept = (sum_y - slope * sum_x) / n;

    let max_y = ys.iter().cloned().fold(f64::NEG_INFINITY, f64::max).abs();

    let max_error = xs
        .iter()
        .zip(ys.iter())
        .map(|(x, y)| {
            let y_pred = slope * x + intercept;
            (y_pred - y).abs() / max_y
        })
        .fold(0.0, f64::max);

    (slope, intercept, max_error)
}

fn fit_error_rate(
    depths: &[usize],
    stds: &[f64],
    drift_std: f64,
    drift_offset_std: f64,
    simulated_drift_deviation: f64,
    simulated_drift_offset_deviation: f64,
) -> FitResults {
    let depths = depths.iter().map(|&d| d as f64).collect::<Vec<_>>();
    let n = depths.len();

    // Linear fit of the worst case drift as a function of depth. We are going
    // to use only a positive linear function so we can assume the drift is
    // always positive.
    let drift_offset = |depth: f64| {
        simulated_drift_offset_deviation * drift_offset_std.abs()
            + simulated_drift_deviation * drift_std * depth
    };

    let corrected_base_2_error_rates: Vec<f64> = depths
        .iter()
        .zip(stds.iter())
        .map(|(&depth, &std)| {
            let left_error_distance = 0.25 + drift_offset(depth);
            let right_error_distance = 0.25 - drift_offset(depth);

            // The approximation fails when the ratio of the error distance to
            // the standard deviation is too large.
            let left_probability = if left_error_distance / std < 30.0 {
                // The `probability_away_from_mean_gaussian_log` function
                // returns the log of the probability of being away from the
                // mean by the given distance in either tail of the
                // distribution. We need to modify this to give us the
                // probability of being away from _one of the tails_ to account
                // for the drift, as we will now be adding two asymmetric tails.
                // Hence we subtract 1.0 from the log value to get only one of
                // the tails (in this case the smaller one).
                (probability_away_from_mean_gaussian_log(left_error_distance, std).log_2() - 1.0)
                    .powf(2.0)
            } else {
                0.0
            };

            let right_probability = if right_error_distance / std < 30.0 {
                (probability_away_from_mean_gaussian_log(right_error_distance, std).log_2() - 1.0)
                    .powf(2.0)
            } else {
                0.0
            };

            (left_probability + right_probability).log2()
        })
        .collect();

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

    let bounds = Bounds::new(&[(Some(0.0), None), (None, None), (None, None)]);
    let options = BoundedOptions {
        max_iter: 10_000,
        ..Default::default()
    };

    // Initial guess for the parameters based on prior experiments.
    let initial_params = Array1::from_vec(vec![6e-5, 30.0, -3.0]);

    let data = Array1::from_vec(corrected_base_2_error_rates.to_vec());

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
            .zip(corrected_base_2_error_rates.iter())
            .map(|(x, y)| (y - function_to_fit(*x, a, b, c)).abs() / y.abs())
            .fold(f64::NEG_INFINITY, f64::max);
        (results, max_error)
    });

    match results {
        Ok((results, max_error)) => FitResults::FitErrorRate {
            a: results.x[0],
            b: results.x[1],
            c: results.x[2],
            equation: FUNCTION_TO_FIT_DESCRIPTION.to_string(),
            max_error,
            base_2_error_at_depth_256: function_to_fit(
                256.0,
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

fn std_analysis(
    sample_count: usize,
    depth: usize,
    params: &Params,
) -> (Vec<CMuxTreeStdDataPoint>, Vec<Vec<Option<f64>>>) {
    // We will use the public key for the encryption because it might generate
    // different noise parameters.
    let secret_key = SecretKey::generate(&params);
    let compute_key = ComputeKey::generate(&secret_key, &params);

    // Generate all bootstraps in parallel and in advance. This could take a lot of memory.
    println!("Generating select lines");
    let now = std::time::Instant::now();
    let progress = ProgressBar::new((depth * 2) as u64);
    progress.set_style(ProgressStyle::with_template(PROGRESS_BAR_TEMPLATE).unwrap());

    let zeros = (0..depth)
        .into_par_iter()
        .map(|_| {
            let ggsw = Arc::new(ggsw_fft_encryption(0, &secret_key, &compute_key, &params));

            progress.inc(1);
            ggsw
        })
        .collect::<Vec<_>>();

    let ones = (0..depth)
        .into_par_iter()
        .map(|_| {
            let ggsw = Arc::new(ggsw_fft_encryption(1, &secret_key, &compute_key, &params));

            progress.inc(1);
            ggsw
        })
        .collect::<Vec<_>>();
    progress.finish_and_clear();
    println!("Time to generate select lines: {:?}", now.elapsed());

    println!("Running each cmux tree");
    let now = std::time::Instant::now();
    let progress = ProgressBar::new(sample_count as u64);
    progress.set_style(ProgressStyle::with_template(PROGRESS_BAR_TEMPLATE).unwrap());

    // We have a vector of size sample_count, each containing a vector of size depth of noise.
    let samples_per_run = (0..sample_count)
        .into_par_iter()
        .map(|_| {
            let run = run_compute_tree(depth, &ones, &zeros, &secret_key, &compute_key, &params);

            progress.inc(1);
            run
        })
        .collect::<Vec<_>>();
    progress.finish_and_clear();
    println!("Time to run cmux tree: {:?}", now.elapsed());

    // Transpose the samples, so now we have a vector of size depth, each
    // containing a vector of size sample_count.
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

            CMuxTreeStdDataPoint {
                mean: rmv.mean(),
                depth: i + 1,
                std,
                measured_err: n_errors as f64 / n_samples as f64,
            }
        })
        .collect::<Vec<_>>();

    let std_raw = samples_per_level_flattened
        .into_iter()
        .map(|level| level.into_iter().map(|res| res.ok()).collect())
        .collect();

    (data_points_per_level, std_raw)
}

fn drift_analysis(
    sample_count: usize,
    depth: usize,
    params: &Params,
) -> (
    Vec<CMuxTreeDriftDataPoint>,
    Vec<Vec<(Option<f64>, Option<f64>)>>,
) {
    let progress = ProgressBar::new(sample_count as u64);
    progress.set_style(ProgressStyle::with_template(PROGRESS_BAR_TEMPLATE).unwrap());

    let samples_per_run = (0..sample_count)
        .into_par_iter()
        .map(|_| {
            let secret_key = SecretKey::generate(&params);
            let compute_key = ComputeKey::generate(&secret_key, &params);
            let zeros = (0..depth)
                .into_iter()
                .map(|_| {
                    let ggsw = Arc::new(ggsw_fft_encryption(0, &secret_key, &compute_key, &params));

                    ggsw
                })
                .collect::<Vec<_>>();

            let ones = (0..depth)
                .into_iter()
                .map(|_| {
                    let ggsw = Arc::new(ggsw_fft_encryption(1, &secret_key, &compute_key, &params));

                    ggsw
                })
                .collect::<Vec<_>>();

            let run_results =
                run_compute_tree(depth, &ones, &zeros, &secret_key, &compute_key, params);

            let run_results = run_results
                .into_iter()
                .map(|(a, b)| (a.ok(), b.ok()))
                .collect::<Vec<_>>();
            progress.inc(1);

            run_results
        })
        .collect::<Vec<_>>();
    progress.finish_and_clear();

    let xs = (1..=depth).map(|x| x as f64).collect::<Vec<_>>();

    let samples_per_run_fit = samples_per_run
        .iter()
        // From what we have seen empirically, the two different trees are
        // independent, so we can just flatten the results.
        .flat_map(|samples_at_depth| {
            // Not sure what to do about the two lines of output. I suppose handle them separately.
            let top_tree_samples = samples_at_depth
                .iter()
                .map(|(a, _)| a.clone().unwrap())
                .collect::<Vec<_>>();
            let bottom_tree_samples = samples_at_depth
                .iter()
                .map(|(_, b)| b.clone().unwrap())
                .collect::<Vec<_>>();

            let (top_tree_drift, top_tree_offset, top_tree_max_error) =
                linear_regression(&xs, &top_tree_samples);
            let (bottom_tree_drift, bottom_tree_offset, bottom_tree_max_error) =
                linear_regression(&xs, &bottom_tree_samples);

            [
                CMuxTreeDriftDataPoint {
                    drift: top_tree_drift,
                    offset: top_tree_offset,
                    max_error: top_tree_max_error,
                },
                CMuxTreeDriftDataPoint {
                    drift: bottom_tree_drift,
                    offset: bottom_tree_offset,
                    max_error: bottom_tree_max_error,
                },
            ]
        })
        .collect::<Vec<_>>();

    (samples_per_run_fit, samples_per_run)
}

pub fn analyze_cmux_tree(cmux_tree_params: &CMuxTreeParameters) -> CMuxTreeDataFile {
    let cmux_tree_params_pretty_json = serde_json::to_string_pretty(cmux_tree_params).unwrap();
    println!("Running with parameters:");
    println!("{}", cmux_tree_params_pretty_json);

    let run_options = cmux_tree_params.run_options;
    let params = cmux_tree_params.parameter_set.clone();

    println!("Running the drift analysis");
    let now = std::time::Instant::now();
    let (drift_data, drift_raw) = drift_analysis(
        run_options.drift_sample_count,
        run_options.drift_depth,
        &params,
    );
    println!("Time to run drift analysis: {:?}", now.elapsed());

    // Calculate parameters for the error fit.
    let drift_std = drift_data
        .iter()
        .fold(RunningMeanVariance::new(), |mut acc, dp| {
            acc.add_sample(dp.drift);
            acc
        })
        .std();

    let drift_offset_std = drift_data
        .iter()
        .fold(RunningMeanVariance::new(), |mut acc, dp| {
            acc.add_sample(dp.offset);
            acc
        })
        .std();

    println!("Running the standard deviation analysis");
    let now = std::time::Instant::now();
    let (std_data, std_raw) = std_analysis(
        run_options.drift_sample_count,
        run_options.std_depth,
        &params,
    );
    println!(
        "Time to run standard deviation analysis: {:?}",
        now.elapsed()
    );

    let (depths, stds) = std_data
        .iter()
        .map(|dp| (dp.depth, dp.std))
        .unzip::<usize, f64, Vec<_>, Vec<_>>();

    let std_raw = if run_options.include_raw {
        std_raw
    } else {
        vec![]
    };

    let fit = fit_error_rate(
        &depths,
        &stds,
        drift_std,
        drift_offset_std,
        run_options.simulated_drift,
        run_options.simulated_drift_offset,
    );

    CMuxTreeDataFile::new(
        cmux_tree_params.clone(),
        fit,
        drift_data,
        drift_raw,
        std_data,
        std_raw,
    )
}
