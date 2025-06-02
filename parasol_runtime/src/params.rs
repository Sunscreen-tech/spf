use serde::{Deserialize, Serialize};
use sunscreen_tfhe::{
    GLWE_1_1024_80, GLWE_1_2048_128, GLWE_5_256_80, GlweDef, LWE_512_80, LWE_637_128, LweDef,
    PolynomialDegree, RadixCount, RadixDecomposition, RadixLog,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The set of parameters for performing FHE computation with Sunscreen's circuit bootstrapping (CBS)
/// approach.
///
/// # Remarks
/// Computation unfolds over multiple ciphertext types encrypted under different keys and parameters.
/// The key intuition about using CBS for computation is to try to perform computation using
/// cheap CMux operations which require GGSW select inputs and GLWE a, b inputs and output.
/// Unfortunately, this interface is awkward and we must convert between ciphertext types as the
/// computation unfolds.
///
/// Ciphertexts convert in a cycle as follows:
/// ```ignore
/// l0 LWE -> l1 GGSW -> l1 GLWE -> l1 LWE -> l0 LWE
/// ```
///
/// where:
/// l1_params are high-noise and encrypt LWE ciphertexts.
/// l1_params contain a medium amount of noise and encrypt LWE, GLWE, and GGSW ciphertexts.
/// l2_params are low noise and are an implementation detail of circuit bootstrapping.
///
/// and each ciphertext encrypts a single 1 or 0 bit.
///
/// * l0 LWE -> l1 GGSW
///   The first step in the cycle is circuit bootstrapping, which simultaneously resets the noise in
///   the input l0 LWE ciphertext and emits a GGSW ciphertext. Internally, circuit bootstrapping
///   first bootstraps to l2 LWE multiple ciphertexts then applies private functional keyswitching
///   to generate the l1 GGSW ciphertext.
/// * l1 GGSW -> l1 GLWE
///   This step actually evaluates functions using trees of multiplexers (via the CMux
///   operation). The CMux operation accepts 2 GLWE ciphertexts, `a` and `b`, and a `GGSW`
///   ciphertext `sel`. The output is a GLWE ciphertext encrypting the same message as `a` when
///   `sel` is 0 and `b` when `sel` is 1.
///
///   To evaluate an N-bit function, we build a multiplexer tree using N layers.
///   At the first layer of the tree, we pass trivial one and zero encryptions as the a and b inputs
///   as the truth table requires as well as the first GGSW. We evaluate each subsequent `i-th`
///   mux layer, using outputs from the `(i-1)-th` layer as `a` and `b` inputs and the `i-th`
///   GGSW encrypted input as `sel`. The final result of this mux tree is an l1 GLWE ciphertext.
/// * l1 GLWE -> l1 LWE
///   We perform sample extraction to produce an LWE encryption of the 0th coefficient of the input
///   GLWE ciphertext's contained message (i.e. the encrypted bit).
/// * l1 LWE -> l0 LWE
///   LWE keyswitching changes the ciphertext's key so we can repeat this process and chain our
///   computation.
///
/// # Radix decomposition
/// Many operations decompose polynomials into the sum of polynomials with smaller coefficients, which
/// get recombobulated with gadget factors during the operation. This is a common technique that
/// reduces noise, but requires a tradeoff between performance and noise growth. Runtime scales
/// linearly with the radix count, so ideally this should be small. However, too small a radix count
/// causes computations to exceed the noise budget and results in wrong results when decrypted.
pub struct Params {
    /// The high noise l0 LWE parameters.
    pub l0_params: LweDef,

    /// The medium noise l1 GLWE parameters.
    pub l1_params: GlweDef,

    /// The low noise l2 GLWE parameters.
    pub l2_params: GlweDef,

    /// The radix decompositon defining the shape of l1 GGSW ciphertexts (the result of circuit
    /// bootstrapping).
    pub cbs_radix: RadixDecomposition,

    /// The radix decomposition internally used during the bootstrapping step of circuit bootstrapping.
    pub pbs_radix: RadixDecomposition,

    /// The decomposition used when keyswitching from l1 LWE to l0 LWE
    pub ks_radix: RadixDecomposition,

    /// The decomposition used during the private function keyswitch step of circuit bootstrapping.
    pub pfks_radix: RadixDecomposition,

    /// Unused and will be removed.
    pub pufks_radix_1: RadixDecomposition,

    /// The decomposition used during scheme switching (currently experimental and poorly documented)
    pub ss_radix: RadixDecomposition,
}

impl Params {
    /// The polynomial degree of L1 ciphertexts and their messages.
    pub fn l1_poly_degree(&self) -> PolynomialDegree {
        self.l1_params.dim.polynomial_degree
    }
}

impl Default for Params {
    fn default() -> Self {
        DEFAULT_128
    }
}

/// A < 80-bit secure parameter set. These numbers are out of date.
///
/// # Remarks
/// Is *not* compatible with RLWE public-key encryption.
pub const DEFAULT_80: Params = Params {
    l0_params: LWE_512_80,
    l1_params: GLWE_1_1024_80,
    l2_params: GLWE_5_256_80,
    cbs_radix: RadixDecomposition {
        radix_log: RadixLog(7),
        count: RadixCount(2),
    },
    pbs_radix: RadixDecomposition {
        radix_log: RadixLog(17),
        count: RadixCount(2),
    },
    pfks_radix: RadixDecomposition {
        radix_log: RadixLog(15),
        count: RadixCount(2),
    },
    pufks_radix_1: RadixDecomposition {
        radix_log: RadixLog(15),
        count: RadixCount(2),
    },
    ks_radix: RadixDecomposition {
        radix_log: RadixLog(1),
        count: RadixCount(12),
    },
    ss_radix: RadixDecomposition {
        radix_log: RadixLog(3),
        count: RadixCount(15),
    },
};

/// The standard 128-bit secure parameter set.
///
/// # Remarks
/// - This parameter set is compatible with RLWE public-key encryption.
/// - The noise exponent (2^x) at a given depth inside a CMUX tree is well
///   approximated (within 3% approximation error, valid up to depth 10,000) by
///   `base_2_error_exponent(depth) = -161785.15 / (depth + 233.42) - 3.54`
///   The error at a computational depth of 1024 is about 2^(-132).
pub const DEFAULT_128: Params = Params {
    l0_params: LWE_637_128,
    l1_params: GLWE_1_2048_128,
    l2_params: GLWE_1_2048_128,
    cbs_radix: RadixDecomposition {
        radix_log: RadixLog(7),
        count: RadixCount(2),
    },
    pbs_radix: RadixDecomposition {
        radix_log: RadixLog(16),
        count: RadixCount(2),
    },
    pfks_radix: RadixDecomposition {
        radix_log: RadixLog(17),
        count: RadixCount(2),
    },
    pufks_radix_1: RadixDecomposition {
        radix_log: RadixLog(15),
        count: RadixCount(2),
    },
    ks_radix: RadixDecomposition {
        radix_log: RadixLog(2),
        count: RadixCount(6),
    },
    ss_radix: RadixDecomposition {
        radix_log: RadixLog(3),
        count: RadixCount(15),
    },
};
