use std::fmt::Display;

use sunscreen_math::security::probability_away_from_mean_gaussian;

pub struct ProbabilityAwayMeanGaussianLog(f64);

impl ProbabilityAwayMeanGaussianLog {
    /// Returns the error probability base 10 log of the given distance from the mean
    pub fn log_10(&self) -> f64 {
        self.0
    }

    /// Returns the error probability base 2 log of the given distance from the mean
    pub fn log_2(&self) -> f64 {
        self.log_10() / std::f64::consts::LOG10_2
    }
}

impl Display for ProbabilityAwayMeanGaussianLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let log_10 = self.log_10();
        write!(f, "10^{:.2}", log_10)
    }
}

/// Gets the log
pub fn probability_away_from_mean_gaussian_log(
    distance: f64,
    std: f64,
) -> ProbabilityAwayMeanGaussianLog {
    ProbabilityAwayMeanGaussianLog(probability_away_from_mean_gaussian(distance, std))
}

pub fn probability_away_from_mean_gaussian_log_binary(std: f64) -> ProbabilityAwayMeanGaussianLog {
    probability_away_from_mean_gaussian_log(0.25, std)
}
