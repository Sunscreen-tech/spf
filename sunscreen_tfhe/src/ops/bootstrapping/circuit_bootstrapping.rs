use num::Complex;
use sunscreen_math::Zero;

use crate::{
    GlweDef, LweDef, OverlaySize, PlaintextBits, PrivateFunctionalKeyswitchLweCount,
    RadixDecomposition, Torus, TorusOps,
    dst::FromMutSlice,
    entities::{
        AutmorphismKeyFftRef, BootstrapKeyFftRef,
        CircuitBootstrappingKeyswitchKeysRef, GgswCiphertextFftRef, GgswCiphertextRef,
        GlevCiphertextRef, GlweCiphertextRef, LweCiphertextListRef, LweCiphertextRef,
        SchemeSwitchKeyFftRef, UnivariateLookupTableRef,
    },
    ops::{
        automorphisms::trace,
        bootstrapping::{
            generalized_programmable_bootstrap, rotate_glwe_negative_monomial_negacyclic,
        },
        ciphertext::{glwe_mod_switch_and_expand_pow_2, sample_extract},
        fft_ops::scheme_switch_fft,
        homomorphisms::lwe_rotate,
        keyswitch::private_functional_keyswitch::private_functional_keyswitch,
    },
    scratch::allocate_scratch_ref,
};

#[deprecated]
#[allow(clippy::too_many_arguments)]
/// Bootstraps a LWE ciphertext to a GGSW ciphertext.
/// Transform [`LweCiphertextRef`] `input` encrypted under parameters `lwe_0` into
/// the  [`GgswCiphertextRef`] `output` encrypted under parameters `glwe_1` with
/// radix decomposition `cbs_radix`. This resets the noise in `output` in the
/// process.
///
/// [`GgswCiphertext`](crate::entities::GgswCiphertext)s can be used as select
/// inputs for [`cmux`](crate::ops::fft_ops::cmux) operations.
///
/// # Deprecated
/// We retain [`circuit_bootstrap_via_pfks`] as a historical artifact
/// for researchers, but we strongly suggest instead using
/// [`circuit_bootstrap_via_trace_and_scheme_switch`], which is around 3x faster
/// and features significantly smaller keys.
///
/// As such, we mark this function as deprecated, but will likely never remove it.
///
/// # Remarks
/// The following diagram illustrates how circuit bootstrapping works
///
/// ![Circuit Bootstrapping](LINK TO GITHUB)
///
/// We perform `cbs_radix.count` programmable bootstrapping (PBS) operations to
/// decompose the original message m under radix `2^cbs_radix.radix_log`. These PBS
/// operations use a bootstrapping key encrypting the level 0 LWE secret key under
/// the level 2 GLWE secret key and internally perform their own radix decomposition
/// parameterized by `pbs_radix`. After performing bootstrapping, we now have
/// `cbs_radix.count` LWE ciphertexts encrypted under the level 2 GLWE secret key
/// (reinterpreted as an LWE key).
///
/// Next, we take each of these `cbs_radix.count` level 2 LWE ciphertexts and
/// perform `glwe_1.dim.size + 1` private functional keyswitching operations (`
/// (glwe_1.dim.size + 1) * cbs_radix.count` in total). For the first `glwe_1.dim.
/// size` rows of the [`GgswCiphertextRef`] output, this multiplies the radix
/// decomposed message by the negative corresponding secret key. For the last
/// row, we simply multiply our radix decomposed messages by 1.
///
/// Recall that [`private_functional_keyswitch`] (PFKS) transforms a list of LWE
/// ciphertexts into a [`GlweCiphertext`](crate::entities::GlweCiphertext). In
/// our case, this list contains a single
/// [`LweCiphertext`](crate::entities::LweCiphertext) for each PFKS operation.
/// Each row of the output [`GgswCiphertext`](crate::entities::GgswCiphertext)
/// corresponds to a different PFKS key, encapsulated in `cbsksk`.
///
/// These PFKS operations switch from a key under parameters `glwe_2` (interpreted
/// as LWE) to `glwe_1` with [`RadixDecomposition`] `pfks_radix`.
///
/// # Panics
/// * If `bsk` is not valid for bootrapping from parameters `lwe_0` to `glwe_2`
///   (reinterpreted as LWE) with radix decomposition `pbs_radix`.
/// * If `cbsksk` is not a valid keyswitch key set for switching from `glwe_2`
///   (reintrerpreted as LWE) to `glwe_1` with `glwe_1.dim.size` entries and radix
///   decomposition `pfks_radix`.
/// * If `output` is not the correct length for a GGSW ciphertext under `glwe_1`
///   parameters with `cbs_radix` decomposition.
/// * If `input` is not a valid LWE ciphertext under `lwe_0` parameters.
/// * If `lwe_0`, `glwe_1`, `glwe_2`, `cbs_radix`, `pfks_radix`, `pbs_radix` are
///   invalid.
///
/// # Example
/// ```
/// use sunscreen_tfhe::{
///   high_level,
///   high_level::{keygen, encryption, fft},
///   entities::GgswCiphertext,
///   ops::bootstrapping::circuit_bootstrap_via_pfks,
///   params::{
///     GLWE_5_256_80,
///     GLWE_1_1024_80,
///     LWE_512_80,
///     PlaintextBits,
///     RadixDecomposition,
///     RadixCount,
///     RadixLog
///   }
/// };
///
/// let pbs_radix = RadixDecomposition {
///   count: RadixCount(2),
///   radix_log: RadixLog(16),
/// };
/// let cbs_radix = RadixDecomposition {
///   count: RadixCount(2),
///   radix_log: RadixLog(5),
/// };
/// let pfks_radix = RadixDecomposition {
///   count: RadixCount(3),
///   radix_log: RadixLog(11),
/// };
///
/// let level_2_params = GLWE_5_256_80;
/// let level_1_params = GLWE_1_1024_80;
/// let level_0_params = LWE_512_80;
///
/// let sk_0 = keygen::generate_binary_lwe_sk(&level_0_params);
/// let sk_1 = keygen::generate_binary_glwe_sk(&level_1_params);
/// let sk_2 = keygen::generate_binary_glwe_sk(&level_2_params);
///
/// let bsk = keygen::generate_bootstrapping_key(
///   &sk_0,
///   &sk_2,
///   &level_0_params,
///   &level_2_params,
///   &pbs_radix,
/// );
/// let bsk =
/// high_level::fft::fft_bootstrap_key(&bsk, &level_0_params, &level_2_params, &pbs_radix);
///
/// let cbsksk = keygen::generate_cbs_ksk(
///   sk_2.to_lwe_secret_key(),
///   &sk_1,
///   &level_2_params.as_lwe_def(),
///   &level_1_params,
///   &pfks_radix,
/// );
///
/// let val = 1;
/// let ct = encryption::encrypt_lwe_secret(val, &sk_0, &level_0_params, PlaintextBits(1));
///
/// let mut ggsw = GgswCiphertext::new(&level_1_params, &cbs_radix);
///
/// // ggsw will contain `val`
/// circuit_bootstrap_via_pfks(
///     &mut ggsw,
///     &ct,
///     &bsk,
///     &cbsksk,
///     &level_0_params,
///     &level_1_params,
///     &level_2_params,
///     &pbs_radix,
///     &cbs_radix,
///     &pfks_radix,
/// );
/// ```
pub fn circuit_bootstrap_via_pfks<S: TorusOps>(
    output: &mut GgswCiphertextRef<S>,
    input: &LweCiphertextRef<S>,
    bsk: &BootstrapKeyFftRef<Complex<f64>>,
    cbsksk: &CircuitBootstrappingKeyswitchKeysRef<S>,
    lwe_0: &LweDef,
    glwe_1: &GlweDef,
    glwe_2: &GlweDef,
    pbs_radix: &RadixDecomposition,
    cbs_radix: &RadixDecomposition,
    pfks_radix: &RadixDecomposition,
) {
    glwe_1.assert_valid();
    glwe_2.assert_valid();
    lwe_0.assert_valid();
    pbs_radix.assert_valid::<S>();
    cbs_radix.assert_valid::<S>();
    pfks_radix.assert_valid::<S>();
    cbsksk.assert_is_valid((glwe_2.as_lwe_def().dim, glwe_1.dim, pfks_radix.count));
    bsk.assert_is_valid((lwe_0.dim, glwe_2.dim, pbs_radix.count));
    output.assert_is_valid((glwe_1.dim, cbs_radix.count));
    input.assert_is_valid(lwe_0.dim);

    // Step 1: use multi-functional PBS to emit the radix-decomposed message into the
    // first \ell coefficients of `lo_noise_glwe`.
    allocate_scratch_ref!(lo_noise_glwe, GlweCiphertextRef<S>, (glwe_2.dim));

    hi_noise_lwe_to_lo_noise_glwe(
        lo_noise_glwe,
        input,
        bsk,
        lwe_0,
        glwe_2,
        pbs_radix,
        cbs_radix,
    );

    // Step 2: Sample extract the first \ell coefficients to lo noise LWE ciphertexts
    // and undo our rotation.
    allocate_scratch_ref!(
        lo_noise_lwe_decomps,
        LweCiphertextListRef<S>,
        (glwe_2.as_lwe_def().dim, cbs_radix.count.0)
    );
    extract_and_rotate_lo_noise_glwe(lo_noise_lwe_decomps, lo_noise_glwe, glwe_2, cbs_radix);

    // Step 3: apply private functional keyswitching on our extracted LWE ciphertexts.
    // This produces our output GLWE ciphertext.
    apply_pfks_on_ggsw_components(
        output,
        &lo_noise_lwe_decomps,
        cbsksk,
        glwe_2,
        glwe_1,
        pfks_radix,
        cbs_radix,
    );
}

#[inline]
/// Sample extract the first \ell coefficients out of the input GLWE and undo the rotation
/// we applied when applying our functional bootstrap.
fn extract_and_rotate_lo_noise_glwe<S>(
    lo_noise_lwe_decomps: &mut LweCiphertextListRef<S>,
    lo_noise_glwe: &GlweCiphertextRef<S>,
    glwe: &GlweDef,
    cbs_radix: &RadixDecomposition,
) where
    S: TorusOps,
{
    allocate_scratch_ref!(extracted, LweCiphertextRef<S>, (glwe.as_lwe_def().dim));

    for (i, lo_noise_lwe_decomp) in lo_noise_lwe_decomps
        .ciphertexts_mut(&glwe.as_lwe_def())
        .enumerate()
    {
        let cur_level = i + 1;
        let plaintext_bits = PlaintextBits((cbs_radix.radix_log.0 * cur_level + 1) as u32);

        sample_extract(extracted, &lo_noise_glwe, i, glwe);

        // Now we rotate our message containing -1 or 1 by 1 (wrt plaintext_bits).
        // This will overflow -1 to 0 and cause 1 to wrap to 2.
        lwe_rotate(
            lo_noise_lwe_decomp,
            extracted,
            Torus::encode(<S as sunscreen_math::One>::one(), plaintext_bits),
            &glwe.as_lwe_def(),
        );
    }
}

#[inline]
/// Given a GLWE ciphertext with a radix decomposed message in the first \ell
/// coefficients, mod switch the ciphertext to add an N^-1 term, then use
/// homomorphic trace to extract the first \ell coefficients into their own
/// GLWE ciphertext, then rotate each of their coefficients to undo the inital
/// rotatiion added for the functional bootstrap.
fn mod_switch_trace_and_rotate<S>(
    lo_noise_glev: &mut GlevCiphertextRef<S>,
    lo_noise_glwe: &GlweCiphertextRef<S>,
    ak: &AutmorphismKeyFftRef<Complex<f64>>,
    glwe: &GlweDef,
    trace_radix: &RadixDecomposition,
    cbs_radix: &RadixDecomposition,
) where
    S: TorusOps,
{
    let shift_amount = glwe.dim.polynomial_degree.0.ilog2() as u32;

    allocate_scratch_ref!(glwe_rotated, GlweCiphertextRef<S>, (glwe.dim));
    allocate_scratch_ref!(glwe_permuted, GlweCiphertextRef<S>, (glwe.dim));
    allocate_scratch_ref!(glwe_shifted, GlweCiphertextRef<S>, (glwe.dim));

    glwe_rotated.clone_from_ref(&lo_noise_glwe);

    for (i, glev_i) in lo_noise_glev.glwe_ciphertexts_mut(&glwe).enumerate() {
        let cur_level = i + 1;
        let plaintext_bits = PlaintextBits((cbs_radix.radix_log.0 * cur_level + 1) as u32);

        // Undo the rotation we applied during functional bootstrapping.
        // We only need to do this for coefficients we're actually extracting.
        glwe_rotated.b_mut(glwe).coeffs_mut()[i] +=
            Torus::encode(<S as sunscreen_math::One>::one(), plaintext_bits);

        // Multiply by x^-i to shift the i'th coefficient into the constant term.
        rotate_glwe_negative_monomial_negacyclic(glwe_permuted, glwe_rotated, i, glwe);

        // Mod shift to implicitly multiply by N^-1
        glwe_mod_switch_and_expand_pow_2(glwe_shifted, &glwe_permuted, glwe, shift_amount);

        // Compute a trace to 0 all but the constant term. A by-product of this multiplies
        // the constant coefficient by N, but this cancels our N^-1 in the previous step,
        // leaving us with the our message's i'th decomposition term.
        trace(glev_i, glwe_shifted, ak, glwe, trace_radix);
    }
}

/// Bootstraps an LWE ciphertext to a GGSW ciphertext. This allows homomorphic computation
/// using CMux trees.
///
/// # Remarks
/// This technique comes from WHS+ (https://eprint.iacr.org/2024/1318.pdf) and is
/// significantly faster than [`circuit_bootstrap_via_pfks`] and has significantly
/// smaller keys.
pub fn circuit_bootstrap_via_trace_and_scheme_switch<S>(
    output: &mut GgswCiphertextFftRef<Complex<f64>>,
    input: &LweCiphertextRef<S>,
    bsk: &BootstrapKeyFftRef<Complex<f64>>,
    ak: &AutmorphismKeyFftRef<Complex<f64>>,
    ssk: &SchemeSwitchKeyFftRef<Complex<f64>>,
    lwe_0: &LweDef,
    glwe_1: &GlweDef,
    pbs_radix: &RadixDecomposition,
    trace_radix: &RadixDecomposition,
    ss_radix: &RadixDecomposition,
    cbs_radix: &RadixDecomposition,
) where
    S: TorusOps,
{
    allocate_scratch_ref!(
        lo_noise_glev,
        GlevCiphertextRef<S>,
        (glwe_1.dim, cbs_radix.count)
    );
    allocate_scratch_ref!(lo_noise_glwe, GlweCiphertextRef<S>, (glwe_1.dim));

    hi_noise_lwe_to_lo_noise_glwe(
        lo_noise_glwe,
        input,
        bsk,
        lwe_0,
        glwe_1,
        pbs_radix,
        cbs_radix,
    );

    mod_switch_trace_and_rotate(
        lo_noise_glev,
        lo_noise_glwe,
        ak,
        glwe_1,
        trace_radix,
        cbs_radix,
    );

    scheme_switch_fft(output, &lo_noise_glev, ssk, glwe_1, cbs_radix, ss_radix);
}

#[inline(always)]
fn hi_noise_lwe_to_lo_noise_glwe<S: TorusOps>(
    output: &mut GlweCiphertextRef<S>,
    input: &LweCiphertextRef<S>,
    bsk: &BootstrapKeyFftRef<Complex<f64>>,
    lwe: &LweDef,
    glwe: &GlweDef,
    pbs_radix: &RadixDecomposition,
    cbs_radix: &RadixDecomposition,
) {
    allocate_scratch_ref!(lut, UnivariateLookupTableRef<S>, (glwe.dim));
    allocate_scratch_ref!(lwe_rotated, LweCiphertextRef<S>, (lwe.dim));
    assert!(cbs_radix.count.0 < 8);

    // Rotate our input by q/4, putting 0 centered on q/4 and 1 centered on
    // -q/4.
    lwe_rotate(
        lwe_rotated,
        input,
        Torus::encode(<S as sunscreen_math::One>::one(), PlaintextBits(2)),
        lwe,
    );

    let log_v = if cbs_radix.count.0.is_power_of_two() {
        cbs_radix.count.0.ilog2()
    } else {
        cbs_radix.count.0.ilog2() + 1
    };

    fill_multifunctional_cbs_decomposition_lut(lut, glwe, cbs_radix);

    generalized_programmable_bootstrap(
        output,
        lwe_rotated,
        lut,
        bsk,
        0,
        log_v,
        lwe,
        glwe,
        pbs_radix,
    );
}

fn fill_multifunctional_cbs_decomposition_lut<S: TorusOps>(
    lut: &mut UnivariateLookupTableRef<S>,
    glwe: &GlweDef,
    cbs_radix: &RadixDecomposition,
) {
    lut.clear();

    // Pick a largish number of levels nobody would ever exceed.
    let mut levels = [Torus::zero(); 16];

    assert!(cbs_radix.count.0 < levels.len());

    // Compute our base decomposition factors.
    // Exploiting the fact that our LUT is negacyclic, we can encode -1 in T_{b^l+1}
    // everywhere. Any lookup < q/2 will give -1 and any lookup > q/2 will
    // give 1. Since we've shifted our input lwe by q/4, a 1 plaintext
    // value will map to 1 and a 0 will map to -1.
    for (i, x) in levels.iter_mut().enumerate() {
        let i = i + 1;
        if i * cbs_radix.radix_log.0 + 1 < S::BITS as usize {
            let plaintext_bits = PlaintextBits((cbs_radix.radix_log.0 * i + 1) as u32);

            let minus_one = (<S as sunscreen_math::One>::one() << plaintext_bits.0 as usize)
                - <S as sunscreen_math::One>::one();
            *x = Torus::encode(minus_one, plaintext_bits);
        }
    }

    // Fill the table with alternating factors padded with zeros to a power of 2
    let log_v = if cbs_radix.count.0.is_power_of_two() {
        cbs_radix.count.0.ilog2()
    } else {
        cbs_radix.count.0.ilog2() + 1
    };

    let v = 0x1usize << log_v;

    for (i, x) in lut
        .glwe_mut()
        .b_mut(glwe)
        .coeffs_mut()
        .iter_mut()
        .enumerate()
    {
        let fn_id = i % v;

        *x = if fn_id < cbs_radix.count.0 {
            levels[fn_id]
        } else {
            Torus::zero()
        };
    }
}

/// Bootstraps a level 2 GLWE ciphertext to a level 1 GLWE ciphertext.
pub fn apply_pfks_on_ggsw_components<S: TorusOps>(
    result: &mut GgswCiphertextRef<S>,
    lwes_2: &LweCiphertextListRef<S>,
    cbsksk: &CircuitBootstrappingKeyswitchKeysRef<S>,
    glwe_2: &GlweDef,
    glwe_1: &GlweDef,
    pfks_radix: &RadixDecomposition,
    cbs_radix: &RadixDecomposition,
) {
    for (glev, pfksk) in result.rows_mut(glwe_1, cbs_radix).zip(cbsksk.keys(
        &glwe_2.as_lwe_def(),
        glwe_1,
        pfks_radix,
    )) {
        for (decomp, glwe) in lwes_2
            .ciphertexts(&glwe_2.as_lwe_def())
            .zip(glev.glwe_ciphertexts_mut(glwe_1))
        {
            private_functional_keyswitch(
                glwe,
                &[decomp],
                pfksk,
                &glwe_2.as_lwe_def(),
                glwe_1,
                pfks_radix,
                &PrivateFunctionalKeyswitchLweCount(1),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, thread_rng};

    use crate::{
        GLWE_1_1024_80, GLWE_1_2048_128, GLWE_5_256_80, LWE_512_80, LWE_637_128, PlaintextBits,
        RadixCount, RadixDecomposition, RadixLog,
        dst::AsSlice,
        entities::{
            AutomorphismKey, AutomorphismKeyFft, GgswCiphertext, GgswCiphertextFft, GlweCiphertext,
            LweCiphertextList, SchemeSwitchKey, SchemeSwitchKeyFft,
        },
        high_level::{self, TEST_LWE_DEF_1, encryption, fft, keygen},
        ops::{
            automorphisms::generate_automorphism_key, bootstrapping::generate_scheme_switch_key,
        },
    };

    use super::*;

    #[test]
    fn can_level_0_to_level_2() {
        let pbs_radix = RadixDecomposition {
            count: RadixCount(2),
            radix_log: RadixLog(16),
        };
        let cbs_radix = RadixDecomposition {
            count: RadixCount(2),
            radix_log: RadixLog(5),
        };

        let glwe_params = GLWE_5_256_80;

        let mut lo_noise_glwe = GlweCiphertext::<u64>::new(&glwe_params);
        let mut low_noise_lwe_decomp =
            LweCiphertextList::<u64>::new(&glwe_params.as_lwe_def(), cbs_radix.count.0);

        let sk = keygen::generate_binary_lwe_sk(&TEST_LWE_DEF_1);
        let glwe_sk = keygen::generate_binary_glwe_sk(&glwe_params);

        let bsk = keygen::generate_bootstrapping_key(
            &sk,
            &glwe_sk,
            &TEST_LWE_DEF_1,
            &glwe_params,
            &pbs_radix,
        );
        let bsk = fft::fft_bootstrap_key(&bsk, &TEST_LWE_DEF_1, &glwe_params, &pbs_radix);

        let lwe = sk.encrypt(0, &TEST_LWE_DEF_1, PlaintextBits(1)).0;

        hi_noise_lwe_to_lo_noise_glwe(
            &mut lo_noise_glwe,
            &lwe,
            &bsk,
            &TEST_LWE_DEF_1,
            &glwe_params,
            &pbs_radix,
            &cbs_radix,
        );

        extract_and_rotate_lo_noise_glwe(
            &mut low_noise_lwe_decomp,
            &lo_noise_glwe,
            &glwe_params,
            &cbs_radix,
        );

        for (i, lwe_2) in low_noise_lwe_decomp
            .ciphertexts(&glwe_params.as_lwe_def())
            .enumerate()
        {
            let cur_level = i + 1;

            let bits = PlaintextBits((cbs_radix.radix_log.0 * cur_level) as u32);

            let actual =
                glwe_sk
                    .to_lwe_secret_key()
                    .decrypt(lwe_2, &glwe_params.as_lwe_def(), bits);

            assert_eq!(actual, 0);
        }

        let lwe = sk.encrypt(1, &TEST_LWE_DEF_1, PlaintextBits(1)).0;

        hi_noise_lwe_to_lo_noise_glwe(
            &mut lo_noise_glwe,
            &lwe,
            &bsk,
            &TEST_LWE_DEF_1,
            &glwe_params,
            &pbs_radix,
            &cbs_radix,
        );

        extract_and_rotate_lo_noise_glwe(
            &mut low_noise_lwe_decomp,
            &lo_noise_glwe,
            &glwe_params,
            &cbs_radix,
        );

        for (i, lwe_2) in low_noise_lwe_decomp
            .ciphertexts(&glwe_params.as_lwe_def())
            .enumerate()
        {
            let cur_level = i + 1;

            let bits = PlaintextBits((cbs_radix.radix_log.0 * cur_level) as u32);

            let actual =
                glwe_sk
                    .to_lwe_secret_key()
                    .decrypt(lwe_2, &glwe_params.as_lwe_def(), bits);

            assert_eq!(actual, 1);
        }
    }

    #[test]
    fn can_circuit_bootstrap_via_pfks() {
        let pbs_radix = RadixDecomposition {
            count: RadixCount(2),
            radix_log: RadixLog(16),
        };
        let cbs_radix = RadixDecomposition {
            count: RadixCount(2),
            radix_log: RadixLog(5),
        };
        let pfks_radix = RadixDecomposition {
            count: RadixCount(3),
            radix_log: RadixLog(11),
        };

        let level_2_params = GLWE_5_256_80;
        let level_1_params = GLWE_1_1024_80;
        let level_0_params = LWE_512_80;

        let sk_0 = keygen::generate_binary_lwe_sk(&level_0_params);
        let sk_1 = keygen::generate_binary_glwe_sk(&level_1_params);
        let sk_2 = keygen::generate_binary_glwe_sk(&level_2_params);

        let bsk = keygen::generate_bootstrapping_key(
            &sk_0,
            &sk_2,
            &level_0_params,
            &level_2_params,
            &pbs_radix,
        );
        let bsk =
            high_level::fft::fft_bootstrap_key(&bsk, &level_0_params, &level_2_params, &pbs_radix);

        let cbsksk = keygen::generate_cbs_ksk(
            sk_2.to_lwe_secret_key(),
            &sk_1,
            &level_2_params.as_lwe_def(),
            &level_1_params,
            &pfks_radix,
        );

        for _ in 0..1 {
            let val = thread_rng().next_u64() % 2;

            let ct = encryption::encrypt_lwe_secret(val, &sk_0, &level_0_params, PlaintextBits(1));

            let mut actual = GgswCiphertext::new(&level_1_params, &cbs_radix);

            #[allow(deprecated)]
            circuit_bootstrap_via_pfks(
                &mut actual,
                &ct,
                &bsk,
                &cbsksk,
                &level_0_params,
                &level_1_params,
                &level_2_params,
                &pbs_radix,
                &cbs_radix,
                &pfks_radix,
            );

            let expected =
                encryption::encrypt_ggsw(val, &sk_1, &level_1_params, &cbs_radix, PlaintextBits(1));

            for (a, e) in actual
                .rows(&level_1_params, &cbs_radix)
                .zip(expected.rows(&level_1_params, &cbs_radix))
            {
                for (i, (a, e)) in a
                    .glwe_ciphertexts(&level_1_params)
                    .zip(e.glwe_ciphertexts(&level_1_params))
                    .enumerate()
                {
                    let plaintext_bits = (i + 1) * cbs_radix.radix_log.0;
                    let plaintext_bits = PlaintextBits(plaintext_bits as u32);

                    let a = encryption::decrypt_glwe(a, &sk_1, &level_1_params, plaintext_bits);
                    let e = encryption::decrypt_glwe(e, &sk_1, &level_1_params, plaintext_bits);

                    assert_eq!(a, e);
                }
            }
        }
    }

    #[test]
    fn can_circuit_bootstrap_via_trace_ss() {
        let pbs_radix = RadixDecomposition {
            count: RadixCount(2),
            radix_log: RadixLog(15),
        };
        let cbs_radix = RadixDecomposition {
            count: RadixCount(4),
            radix_log: RadixLog(4),
        };
        let tr_radix = RadixDecomposition {
            count: RadixCount(6),
            radix_log: RadixLog(7),
        };
        let ss_radix = RadixDecomposition {
            count: RadixCount(2),
            radix_log: RadixLog(17),
        };
        let lwe = LWE_637_128;
        let glwe = GLWE_1_2048_128;

        let lwe_sk = keygen::generate_binary_lwe_sk(&lwe);
        let glwe_sk = keygen::generate_binary_glwe_sk(&glwe);

        let bsk = keygen::generate_bootstrapping_key(&lwe_sk, &glwe_sk, &lwe, &glwe, &pbs_radix);
        let bsk = fft::fft_bootstrap_key(&bsk, &lwe, &glwe, &pbs_radix);

        let mut ssk = SchemeSwitchKey::<u64>::new(&glwe, &ss_radix);
        generate_scheme_switch_key(&mut ssk, &glwe_sk, &glwe, &ss_radix);
        let mut ssk_fft = SchemeSwitchKeyFft::new(&glwe, &ss_radix);
        ssk.fft(&mut ssk_fft, &glwe, &ss_radix);

        let mut ak = AutomorphismKey::<u64>::new(&glwe, &tr_radix);
        generate_automorphism_key(&mut ak, &glwe_sk, &glwe, &tr_radix);
        let mut ak_fft = AutomorphismKeyFft::new(&glwe, &tr_radix);
        ak.fft(&mut ak_fft, &glwe, &tr_radix);

        for b in [0, 1] {
            let ct = lwe_sk.encrypt(b, &lwe, PlaintextBits(1)).0;

            let mut actual = GgswCiphertextFft::new(&glwe, &cbs_radix);

            circuit_bootstrap_via_trace_and_scheme_switch(
                &mut actual,
                &ct,
                &bsk,
                &ak_fft,
                &ssk_fft,
                &lwe,
                &glwe,
                &pbs_radix,
                &tr_radix,
                &ss_radix,
                &cbs_radix,
            );

            let mut actual_ifft = GgswCiphertext::new(&glwe, &cbs_radix);

            dbg!(actual.as_slice());

            actual.ifft(&mut actual_ifft, &glwe, &cbs_radix);

            let expected =
                encryption::encrypt_ggsw(b, &glwe_sk, &glwe, &cbs_radix, PlaintextBits(1));

            for (a, e) in actual_ifft
                .rows(&glwe, &cbs_radix)
                .zip(expected.rows(&glwe, &cbs_radix))
            {
                for (i, (a, e)) in a
                    .glwe_ciphertexts(&glwe)
                    .zip(e.glwe_ciphertexts(&glwe))
                    .enumerate()
                {
                    let plaintext_bits = (i + 1) * cbs_radix.radix_log.0;
                    let plaintext_bits = PlaintextBits(plaintext_bits as u32);

                    let a = encryption::decrypt_glwe(a, &glwe_sk, &glwe, plaintext_bits);
                    let e = encryption::decrypt_glwe(e, &glwe_sk, &glwe, plaintext_bits);

                    assert_eq!(a, e);
                }
            }
        }
    }
}
