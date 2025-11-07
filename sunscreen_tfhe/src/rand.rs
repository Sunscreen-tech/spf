use std::{fmt::Debug, hash::Hash};

use rand::{Rng, rng};
use rand_chacha::rand_core::{RngCore, SeedableRng};

// Re-export ChaCha12Rng for cross-platform deterministic generation
pub use rand_chacha::ChaCha12Rng as SeededRng;
use rand_distr::Normal;
use serde::{Deserialize, Serialize};

use crate::{
    entities::PolynomialRef,
    math::{Torus, TorusOps},
};

/// A cryptographically secure seed for deterministic key generation.
///
/// Contains 256 bits of entropy for security. Keys generated from the same seed
/// will be identical across all platforms and architectures.
///
/// # Examples
///
/// ```
/// use sunscreen_tfhe::rand::Seed;
///
/// // Generate a random seed
/// let seed = Seed::generate();
///
/// // Or create from known bytes for reproducible results
/// let fixed_seed = Seed::from_bytes([42u8; 32]);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Seed([u8; 32]);

impl Seed {
    /// Generate a cryptographically secure random seed.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rng().fill_bytes(&mut bytes);
        Seed(bytes)
    }

    /// Create a seed from existing bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Seed(bytes)
    }

    /// Access the underlying bytes of the seed.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create a deterministic RNG from this seed.
    ///
    /// Uses ChaCha12Rng for cross-platform consistency.
    ///
    /// # Examples
    ///
    /// ```
    /// use sunscreen_tfhe::rand::Seed;
    ///
    /// let seed = Seed::from_bytes([42u8; 32]);
    /// let mut rng = seed.create_rng();
    /// ```
    pub fn create_rng(&self) -> SeededRng {
        SeededRng::from_seed(*self.as_bytes())
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(transparent)]
/// The standard deviation of a Gaussian distribution normalized over the torus
/// `T_q`.
pub struct Stddev(pub f64);

impl Hash for Stddev {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Git outta here you no good yellow bellied total ordering ruining varmint
        assert!(!self.0.is_nan());

        self.0.to_bits().hash(state);
    }
}

impl PartialEq for Stddev {
    fn eq(&self, other: &Self) -> bool {
        assert!(!self.0.is_nan());
        assert!(!other.0.is_nan());

        self.0.eq(&other.0)
    }
}

impl Eq for Stddev {}

/// Generate a normal torus element using a sampling function
fn normal_torus_with_sampler<S: TorusOps, F>(std: Stddev, sampler: F) -> Torus<S>
where
    F: FnOnce(&Normal<f64>) -> f64,
{
    let dist = Normal::new(0., std.0).expect("Standard deviation must be finite and non-negative");
    let sample = sampler(&dist);
    let q = (S::BITS as f64).exp2();
    let e = f64::round(sample * q) as i64;
    let e: u64 = i64::cast_unsigned(e);
    Torus::from(S::from_u64(e))
}

/// Sample a random torus element from the a normal distribution
/// with a mean of 0 and the given stddev
pub fn normal_torus<S: TorusOps>(std: Stddev) -> Torus<S> {
    normal_torus_with_sampler(std, |dist| rng().sample(dist))
}

/// Generate a random torus element uniformly
pub fn uniform_torus<S: TorusOps>() -> Torus<S> {
    Torus::from(S::from_u64(rng().next_u64()))
}

/// Generate a random binary torus element
pub fn binary<S: TorusOps>() -> S {
    S::from_u64(rng().next_u64() % 2)
}

/// Fill in a polynomial with random binary coefficients
pub fn binary_torus_polynomial<S: TorusOps>(out: &mut PolynomialRef<S>) {
    for c in out.coeffs_mut().iter_mut() {
        *c = binary();
    }
}

/// Sample a random polynomial with coefficients chosen from a normal distribution
/// with a mean of 0 and the given stddev
pub fn normal_torus_polynomial<S: TorusOps>(out: &mut PolynomialRef<Torus<S>>, std: Stddev) {
    for c in out.coeffs_mut().iter_mut() {
        *c = normal_torus(std);
    }
}

/// Generate a random binary torus element using a seeded RNG
pub fn binary_with_seed<S: TorusOps>(rng: &mut SeededRng) -> S {
    S::from_u64(rng.next_u64() % 2)
}

/// Generate a random torus element uniformly using a seeded RNG
pub fn uniform_torus_with_seed<S: TorusOps>(rng: &mut SeededRng) -> Torus<S> {
    Torus::from(S::from_u64(rng.next_u64()))
}

/// Sample a random torus element from a normal distribution using a seeded RNG
pub fn normal_torus_with_seed<S: TorusOps>(std: Stddev, rng: &mut SeededRng) -> Torus<S> {
    normal_torus_with_sampler(std, |dist| rng.sample(dist))
}

#[cfg(test)]
mod tests {
    use std::mem::transmute_copy;

    use crate::math::ToF64;

    use super::*;

    #[test]
    fn can_produce_random_torus() {
        pub fn case<S, I>()
        where
            S: TorusOps,
            I: ToF64 + Copy + Debug,
        {
            let q = (S::BITS as f64).exp2();
            let n: i32 = 100_000;

            let dev = Stddev(0.000_448_516_698_238_696_5);

            let data = (0..n)
                .map(|_| {
                    let t = normal_torus::<S>(dev).inner();
                    unsafe { transmute_copy::<S, I>(&t) }
                })
                .collect::<Vec<_>>();

            // Reinterpreting the torus points as i64 values should give a mean of approximately zero.
            let mean = data
                .iter()
                .copied()
                .map(|x| x.to_f64())
                .fold(0., |s, x| s + x)
                / (q * n as f64);

            assert!(mean < 1e-5);

            // Scale the integer values back to the range [0, 1) and compute the stddev
            let measured_std = data
                .iter()
                .copied()
                .map(|x| {
                    let val = (x.to_f64() / q) - mean;

                    val * val
                })
                .fold(0f64, |s, x| s + x)
                / n as f64;

            let measured_std = measured_std.sqrt();

            assert!((measured_std - dev.0).abs() < 0.00001);
        }

        case::<u32, i32>();
        case::<u64, i64>();
    }

    #[test]
    fn test_seed_generation() {
        // Test that different generated seeds are different
        let seed1 = Seed::generate();
        let seed2 = Seed::generate();
        assert_ne!(seed1.as_bytes(), seed2.as_bytes());
    }

    #[test]
    fn test_seed_from_bytes() {
        let bytes = [42u8; 32];
        let seed = Seed::from_bytes(bytes);
        assert_eq!(seed.as_bytes(), &bytes);
    }

    #[test]
    fn test_seeded_binary_deterministic() {
        let seed = Seed::from_bytes([1u8; 32]);
        let mut rng1 = seed.create_rng();
        let mut rng2 = seed.create_rng();

        for _ in 0..10 {
            let val1 = binary_with_seed::<u64>(&mut rng1);
            let val2 = binary_with_seed::<u64>(&mut rng2);
            assert_eq!(val1, val2);
            assert!(val1 == 0 || val1 == 1);
        }
    }

    #[test]
    fn test_seeded_uniform_torus_deterministic() {
        let seed = Seed::from_bytes([2u8; 32]);
        let mut rng1 = seed.create_rng();
        let mut rng2 = seed.create_rng();

        for _ in 0..10 {
            let val1 = uniform_torus_with_seed::<u64>(&mut rng1);
            let val2 = uniform_torus_with_seed::<u64>(&mut rng2);
            assert_eq!(val1.inner(), val2.inner());
        }
    }

    #[test]
    fn test_seeded_normal_torus_deterministic() {
        let seed = Seed::from_bytes([3u8; 32]);
        let std = Stddev(1e-16);
        let mut rng1 = seed.create_rng();
        let mut rng2 = seed.create_rng();

        for _ in 0..10 {
            let val1 = normal_torus_with_seed::<u64>(std, &mut rng1);
            let val2 = normal_torus_with_seed::<u64>(std, &mut rng2);
            assert_eq!(val1.inner(), val2.inner());
        }
    }

    #[test]
    fn test_different_seeds_produce_different_values() {
        let seed1 = Seed::from_bytes([1u8; 32]);
        let seed2 = Seed::from_bytes([2u8; 32]);

        let mut rng1 = seed1.create_rng();
        let mut rng2 = seed2.create_rng();

        let val1 = uniform_torus_with_seed::<u64>(&mut rng1);
        let val2 = uniform_torus_with_seed::<u64>(&mut rng2);
        assert_ne!(val1.inner(), val2.inner());
    }
}
