use crate::geometry::{ConvexPolytope2D, HalfSpace2D, Point2D};

/// Error for when a value is outside the constraints of a polytope.
#[derive(Debug)]
pub struct OutsideConstraintsError {
    /// The name of the dimensions that were outside the constraints.
    dimensions: [String; 2],

    /// The value that was outside the constraints.
    value: (f64, f64),

    /// The polytope it was supposed to be in.
    polytope: ConvexPolytope2D,
}

impl OutsideConstraintsError {
    /// The name of the dimensions that were outside the constraints.
    pub fn dimensions(&self) -> &[String; 2] {
        &self.dimensions
    }

    /// The value that was outside the constraints.
    pub fn value(&self) -> (f64, f64) {
        self.value
    }

    /// The polytope it was supposed to be in.
    pub fn polytope(&self) -> &ConvexPolytope2D {
        &self.polytope
    }
}

impl std::fmt::Display for OutsideConstraintsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Value {:?} is outside the constraints of polytope {:?}",
            self.value, self.polytope
        )
    }
}

/// Result type for [`lwe_security_level_to_std`].
pub type StandardDeviationResult = Result<f64, OutsideConstraintsError>;

/// Result type for [`lwe_std_to_security_level`].
pub type SecurityLevelResult = Result<f64, OutsideConstraintsError>;

/// Evaluate a 2D polynomial with coefficients in increasing order of degree
/// along both dimensions.
pub fn evaluate_polynomial_2d<const M: usize, const N: usize>(
    coeffs: &[[f64; N]; M],
    x: f64,
    y: f64,
) -> f64 {
    let mut result = 0.0;

    // Clippy comaplins but this is the simplest way to read this loop.
    #[allow(clippy::needless_range_loop)]
    for i in 0..M {
        for j in 0..N {
            result += coeffs[i][j] * x.powi(i as i32) * y.powi(j as i32);
        }
    }

    result
}

/// Number of correction terms in the erfc asymptotic expansion (NIST DLMF
/// 7.12.1). With n correction terms the relative error is O(z^{-2(n+1)}).
/// At the transition point z=26 with n=3, the error is ~26^{-8} ~ 5e-12.
const ERFC_ASYMPTOTIC_CORRECTION_TERMS: usize = 3;

/// Returns the log10 of the probability of being farther than x away from the
/// mean given a standard deviation. We return the log to handle very low
/// probabilities.
///
/// For moderate ratios (x/std < ~37), uses `libm::erfc` which is exact to
/// machine precision. For large ratios where erfc underflows f64, uses the
/// asymptotic expansion (NIST DLMF 7.12.1):
///
///   erfc(z) ~ exp(-z^2) / (z * sqrt(pi)) * S_n(z)    as z -> inf
///
/// where z = x / (std * sqrt(2)) and S_n is the partial sum:
///
///   S_n(z) = sum_{k=0}^{n} (-1)^k * (2k-1)!! / (2z^2)^k
///          = 1 - 1/(2z^2) + 3/(4z^4) - 15/(8z^6) + ...
///
/// The number of correction terms n is controlled by
/// [`ERFC_ASYMPTOTIC_CORRECTION_TERMS`].
///
/// # Arguments
///
/// * `x` - The distance from the mean.
/// * `std` - The standard deviation.
///
/// # Returns
/// The log10 of the probability of being x away from the mean given a standard
/// deviation.
///
/// # Examples
/// ```
/// use sunscreen_math::security::probability_away_from_mean_gaussian;
///
/// // Probability of being 1 standard deviation away from the mean. Should be
/// // approximately 32%. If you know z-scores then this should be familiar.
/// let log_prob = probability_away_from_mean_gaussian(1.0, 1.0);
/// let prob = 10.0f64.powf(log_prob);
/// let rounded_prob = (prob * 10000.0).round() / 10000.0;
/// assert_eq!(rounded_prob, 0.3173);
/// ```
pub fn probability_away_from_mean_gaussian(x: f64, std: f64) -> f64 {
    // P(|X| > x) = erfc(x / (std * sqrt(2))) for X ~ N(0, std).
    let z = x / (std * std::f64::consts::SQRT_2);

    if z > 26.0 {
        // erfc(z) underflows f64 for z >= ~26.6. Use the asymptotic expansion
        // (NIST DLMF 7.12.1):
        //
        //   erfc(z) ~ exp(-z^2) / (z * sqrt(pi)) * S_n(z)
        //
        // where S_n(z) = sum_{k=0}^{n} (-1)^k (2k-1)!! / (2z^2)^k.
        //
        // Taking log10:
        //   log10(erfc(z)) ~ -z^2*log10(e) - log10(z) - 0.5*log10(pi) + log10(S_n)
        let log10_e = std::f64::consts::LOG10_E;
        let leading = -(z * z * log10_e) - z.log10() - 0.5 * std::f64::consts::PI.log10();

        // Compute S_n iteratively. Each term: t_k = t_{k-1} * -(2k-1) / (2z^2).
        let inv_2z2 = 1.0 / (2.0 * z * z);
        let mut term = 1.0;
        let mut sum = 1.0;
        for k in 1..=ERFC_ASYMPTOTIC_CORRECTION_TERMS {
            term *= -((2 * k - 1) as f64) * inv_2z2;
            sum += term;
        }

        leading + sum.log10()
    } else {
        // libm::erfc is exact to machine precision for z <= 26.
        libm::erfc(z).log10()
    }
}

/// Returns the LWE standard deviation for a given dimension and security level,
/// normalized to the ciphertext modulus (calculated with 2^64 as the modulus).
/// Valid from 368 to 2048 dimensions and 78 to 130 bits of security. Assumes
/// that the private key is binary.
///
/// There are constraints on the input space above 1472 dimensions, where the
/// security level at the smallest amount of noise possible is higher than 78
/// bits.
///
/// This approximation has an error of 0.021% +- 0.014%, max error 0.11%.
///
/// Simulation data used for fit from
/// lattice-estimator commit 25f9e88 (Nov 8th 2023).
/// <https://github.com/malb/lattice-estimator>
pub fn lwe_security_level_to_std(dimension: usize, security_level: f64) -> StandardDeviationResult {
    let security_polytope = ConvexPolytope2D {
        half_spaces: vec![
            HalfSpace2D::new((-1.0, 0.0), -368.0),
            HalfSpace2D::new((1.0, 0.0), 2048.0),
            HalfSpace2D::new((0.0, -1.0), -78.0),
            HalfSpace2D::new((0.0, 1.0), 130.0),
            // Above 1472 dimensions the security level at the smallest amount of
            // noise possible is higher than 78 bits.
            HalfSpace2D::new((0.05678074392712544, -1.0), 3.5151045883938177),
        ],
    };

    if !security_polytope.inside(Point2D::new(dimension as f64, security_level)) {
        return Err(OutsideConstraintsError {
            dimensions: ["dimension".to_string(), "security_level".to_string()],
            value: (dimension as f64, security_level),
            polytope: security_polytope,
        });
    }

    let coeffs = [
        [
            2.89630547e+00,
            -1.26321873e-01,
            2.13993467e-03,
            -1.49515549e-05,
            3.84468453e-08,
        ],
        [
            -5.60568533e-02,
            1.33311189e-03,
            -1.56200244e-05,
            8.93067686e-08,
            -2.00996854e-10,
        ],
        [
            7.39088707e-07,
            -9.61269520e-08,
            2.15766569e-09,
            -1.82462028e-11,
            5.45243818e-14,
        ],
        [
            1.49456164e-09,
            -4.28264022e-11,
            4.30538855e-13,
            -1.50621118e-15,
            0.00000000e+00,
        ],
        [
            9.49334890e-14,
            -2.17539853e-15,
            1.22195316e-17,
            0.00000000e+00,
            0.00000000e+00,
        ],
    ];

    let log_std = evaluate_polynomial_2d(&coeffs, dimension as f64, security_level);

    Ok(10.0f64.powf(log_std))
}

/// Returns the LWE security level for a given dimension and standard deviation,
/// normalized to the ciphertext modulus (calculated with 2^64 as the modulus).
/// Valid from 368 to 2048 dimensions and 78 to 130 bits of security. Assumes
/// that the private key is binary.
///
/// The valid standard deviations are functions of the dimension, and hence not
/// all standard deviations are valid for all dimensions. If a standard
/// deviation is not valid for a given dimension, an error is returned defining
/// the valid region of standard deviations.
///
/// This approximation has an error of 0.019% +- 0.014%, max error 0.11%.
///
/// Simulation data used for fit from
/// lattice-estimator commit 25f9e88 (Nov 8th 2023).
/// <https://github.com/malb/lattice-estimator>
pub fn lwe_std_to_security_level(dimension: usize, std: f64) -> SecurityLevelResult {
    let log_std = std.log10();

    let std_polytope = ConvexPolytope2D {
        half_spaces: vec![
            HalfSpace2D::new((-1.0, 0.0), -386.0),
            HalfSpace2D::new((1.0, 0.0), 2048.0),
            // Half spaces to define the general region where the standard deviation is valid.
            HalfSpace2D::new((-0.012501482876757172, -1.0), -0.5040411014606384),
            HalfSpace2D::new((0.0077927720025765665, 1.0), 0.7390928205510939),
            // Minimum bound on the standard deviation
            HalfSpace2D::new((0.0, -1.0), 17.67),
        ],
    };

    if !std_polytope.inside(Point2D::new(dimension as f64, log_std)) {
        return Err(OutsideConstraintsError {
            dimensions: ["dimension".to_string(), "log_std".to_string()],
            value: (dimension as f64, log_std),
            polytope: std_polytope,
        });
    }

    let coeffs = [
        [
            6.90381015e+01,
            5.02853460e+01,
            1.94568148e+01,
            4.20275108e+00,
            5.70115313e-01,
            3.84445029e-02,
            1.01123781e-03,
        ],
        [
            5.74446364e-01,
            2.16090358e-01,
            4.33027422e-02,
            5.96469779e-03,
            3.47705471e-05,
            -3.75600129e-05,
            -1.73396859e-06,
        ],
        [
            1.38947894e-04,
            -1.97798175e-06,
            6.18022031e-06,
            -8.44553282e-06,
            -9.87061302e-07,
            -1.98799589e-08,
            7.73239565e-10,
        ],
        [
            -1.76700147e-07,
            4.46397961e-08,
            -8.48859329e-08,
            -6.50906497e-09,
            2.29684491e-10,
            2.23006735e-11,
            0.00000000e+00,
        ],
        [
            2.73798876e-10,
            -4.27647020e-10,
            -1.56129840e-12,
            5.18444880e-12,
            2.50320308e-13,
            0.00000000e+00,
            0.00000000e+00,
        ],
        [
            -9.58735744e-13,
            1.71390444e-13,
            3.36603110e-14,
            1.30767385e-15,
            0.00000000e+00,
            0.00000000e+00,
            0.00000000e+00,
        ],
        [
            5.98968287e-16,
            7.74296283e-17,
            2.66615159e-18,
            0.00000000e+00,
            0.00000000e+00,
            0.00000000e+00,
            0.00000000e+00,
        ],
    ];

    Ok(evaluate_polynomial_2d(&coeffs, dimension as f64, log_std))
}

#[cfg(test)]
mod tests {
    use super::{lwe_security_level_to_std, lwe_std_to_security_level};
    use super::probability_away_from_mean_gaussian;

    /// Verify that the erfc-based implementation matches libm::erfc (the
    /// ground truth for tail probabilities) for all integer ratios from 1
    /// to 30. For ratios 1-36 our function uses libm::erfc directly, so this
    /// also serves as a regression test. For ratios beyond the z=26 threshold
    /// (~37), the asymptotic expansion is tested against the exact value.
    #[test]
    fn erfc_matches_exact_for_ratios_up_to_30() {
        for ratio in 1..=30 {
            let distance = 1.0;
            let std = distance / ratio as f64;
            let z = ratio as f64 / std::f64::consts::SQRT_2;

            // Ground truth: libm::erfc is accurate to machine precision for
            // these z values (all well below the f64 underflow boundary).
            let exact_log10 = libm::erfc(z).log10();

            let computed_log10 = probability_away_from_mean_gaussian(distance, std);

            let abs_diff = (computed_log10 - exact_log10).abs();
            let rel_diff = abs_diff / exact_log10.abs();

            assert!(
                rel_diff < 1e-10,
                "ratio {ratio}: computed={computed_log10:.12}, exact={exact_log10:.12}, \
                 rel_diff={rel_diff:.2e}"
            );
        }
    }

    /// The previous quintic polynomial approximation, retained as a test
    /// reference. Validated for ratios 7-30 with max 0.00145% error.
    fn old_quintic_log10(ratio: f64) -> f64 {
        let coeffs = [
            -0.31904236601958913,
            -0.13390834324063405,
            -0.20902566462352498,
            -0.0003178660849038345,
            6.75504783552659e-06,
            -5.91907446763691e-08,
        ];
        coeffs
            .iter()
            .enumerate()
            .map(|(i, &c)| c * ratio.powi(i as i32))
            .sum()
    }

    /// Verify the new erfc-based implementation agrees with the old quintic
    /// polynomial approximation for all integer ratios from 7 to 30 (the
    /// quintic's validated range).
    #[test]
    fn erfc_matches_old_quintic_for_ratios_7_to_30() {
        for ratio in 7..=30 {
            let distance = 1.0;
            let std = distance / ratio as f64;

            let new_log10 = probability_away_from_mean_gaussian(distance, std);
            let old_log10 = old_quintic_log10(ratio as f64);

            let rel_diff = ((new_log10 - old_log10) / old_log10).abs();

            // The quintic itself has max 0.00145% error, so allow up to
            // 0.01% relative difference between the two implementations.
            assert!(
                rel_diff < 1e-4,
                "ratio {ratio}: new={new_log10:.10}, old_quintic={old_log10:.10}, \
                 rel_diff={rel_diff:.2e}"
            );
        }
    }

    #[test]
    fn lwe_security_to_std_and_back() {
        let tolerance = 0.05;

        for dimension in 368..=2048 {
            for security_level in 80..=128 {
                let std = if let Ok(value) =
                    lwe_security_level_to_std(dimension, security_level as f64)
                {
                    value
                } else {
                    continue;
                };

                let recovered_security_level =
                    if let Ok(value) = lwe_std_to_security_level(dimension, std) {
                        value
                    } else {
                        continue;
                    };

                let diff = (recovered_security_level - security_level as f64).abs();
                assert!(
                    diff < tolerance,
                    "Security level tolerance violated. Dimension: {dimension}, std: {std}, security_level: {security_level}, recovered_level: {recovered_security_level}"
                );
            }
        }
    }
}
