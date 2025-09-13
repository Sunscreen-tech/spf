use num::Complex;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};

use crate::{
    AddendCount, CarryBits, GlweDef, LweDef, OverlaySize, PlaintextBits, RadixDecomposition, Torus,
    TorusOps,
    dst::FromMutSlice,
    entities::{
        BivariateLookupTableRef, BootstrapKeyFftRef, BootstrapKeyRef, GgswCiphertextFftRef,
        GgswCiphertextRef, GlweCiphertextFft, GlweCiphertextFftRef, GlweCiphertextRef,
        GlweSecretKeyRef, LweCiphertextRef, LweSecretKeyRef, Polynomial, PolynomialRef,
        UnivariateLookupTableRef, bootstrap_key_bundle_size,
    },
    ops::{
        bootstrapping::rotate_glwe_positive_monomial_negacyclic,
        ciphertext::{
            add_lwe_inplace, lwe_ciphertext_modulus_switch, sample_extract,
            scalar_mul_ciphertext_mad,
        },
        encryption::encrypt_ggsw_ciphertext_scalar,
        fft_ops::{cmux, glwe_ggsw_mad},
        homomorphisms::{
            add_assign_ggsw_ciphertexts_fft, mul_ggsw_ciphertext_positive_monomial_fft,
            sub_assign_ggsw_ciphertexts_fft, sub_ggsw_ciphertexts_fft,
        },
    },
    scratch::allocate_scratch_ref,
};

use super::rotate_glwe_negative_monomial_negacyclic;

/// Generate a bootstrap key from a LWE secret key to a GLWE secret key.
///
/// Mathematically, this key is a list of GGSW ciphertexts, one for each bit of
/// the secret key being encrypted.
///
/// See
/// [`programmable_bootstrap_univariate`](crate::ops::bootstrapping::programmable_bootstrap_univariate)
/// for an example of how to use this key.
pub fn generate_bootstrap_key<S>(
    bootstrap_key: &mut BootstrapKeyRef<S>,
    sk_to_encrypt: &LweSecretKeyRef<S>,
    sk: &GlweSecretKeyRef<S>,
    lwe: &LweDef,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
    addend_count: AddendCount,
) where
    S: TorusOps,
{
    lwe.assert_valid();
    glwe.assert_valid();
    radix.assert_valid::<S>();
    bootstrap_key.assert_is_valid((lwe.dim, glwe.dim, radix.count, addend_count));
    sk.assert_is_valid(glwe.dim);
    sk_to_encrypt.assert_is_valid(lwe.dim);
    addend_count.assert_valid();

    let bundle_size = bootstrap_key_bundle_size(addend_count);

    sk_to_encrypt
        .s()
        .par_chunks(addend_count.0 as usize)
        .zip(bootstrap_key.rows_par_mut(glwe, radix).chunks(bundle_size))
        .for_each(|(s_i, mut ggsw)| {
            generate_key_bundle(ggsw.as_mut_slice(), s_i, sk, glwe, radix, PlaintextBits(1));
        });
}

fn generate_key_bundle<S>(
    enc_sk: &mut [&mut GgswCiphertextRef<S>],
    sk_bits: &[S],
    glwe_sk: &GlweSecretKeyRef<S>,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
    plaintext_bits: PlaintextBits,
) where
    S: TorusOps,
{
    let bundle_size = bootstrap_key_bundle_size(AddendCount(sk_bits.len() as u32));
    assert_eq!(bundle_size, enc_sk.len());

    // If our bundle size is 1, just encrypt the bit as we'll use the CMUX method
    // during bootstrapping.
    if sk_bits.len() == 1 {
        encrypt_ggsw_ciphertext_scalar(enc_sk[0], sk_bits[0], glwe_sk, glwe, radix, plaintext_bits);

        return;
    }

    // Otherwise, generate the keybundle of all permutations of s_i and !s_i.
    //
    // Iterate over all the truth table configurations for the bundle of secret key bits.
    // If the j'th bit of i is a zero, we invert s_i for its contributing in the product
    // of s_i terms. Otherwise, we just take s_i as-is.
    #[allow(clippy::needless_range_loop)]
    for i in 0..bundle_size {
        let kb = sk_bits
            .iter()
            .enumerate()
            .map(|(j, x)| {
                if (i >> j) & 0x1 == 1 {
                    *x
                } else {
                    !*x & <S as num::One>::one()
                }
            })
            .fold(<S as num::One>::one(), |s, x| s & x);

        encrypt_ggsw_ciphertext_scalar(enc_sk[i], kb, glwe_sk, glwe, radix, plaintext_bits);
    }
}

/// Generate a negacyclic LUT for bootstrapping. Another name for this structure
/// is a test polynomial.
///
/// The map function passed in must have the following negacyclic property,
/// where N is the size of the polynomial:
///
/// ```text
/// map(N + i) = -map(i)
/// ```
#[allow(dead_code)]
fn generate_negacyclic_lut<S, F>(
    output: &mut Polynomial<Torus<S>>,
    map: F,
    params: &GlweDef,
    plaintext_bits: PlaintextBits,
) where
    S: TorusOps,
    F: Fn(u64) -> u64,
{
    let p = (1 << plaintext_bits.0) as u64;
    let n = params.dim.polynomial_degree.0 as u64;

    let stride = 2 * n / p;

    let delta = S::BITS - plaintext_bits.0;

    let c = output.coeffs_mut();

    // Written out this way because when we get to programmable boot strapping,
    // this will involve replacing p_i with f(p_i)
    for (j, p_i_unmapped) in (0..=p / 2).enumerate() {
        let j = j as u64;

        let p_i = map(p_i_unmapped);
        assert!(
            p_i < p,
            "The map function must produce a value less than p. Map produced the relation ({p_i_unmapped} -> {p_i})"
        );

        let p_i = p_i << delta;

        if j == 0 {
            for k in 0..(stride / 2) {
                c[k as usize] = Torus::from(S::from_u64(p_i));
            }
        } else if j == p / 2 {
            for k in (n - (stride / 2))..n {
                c[k as usize] = Torus::from(S::from_u64(p_i));
            }
        } else {
            for k in (stride / 2 + (j - 1) * stride)..(stride / 2 + j * stride) {
                c[k as usize] = Torus::from(S::from_u64(p_i));
            }
        }
    }
}

/// Generates a lookup table (LUT) to be used with bootstrapping. This LUT is
/// not negacyclic, and hence must be used with LWE inputs that have at least
/// one padding bit.
///
/// The input `map` is used for generating programmable bootstrapping LUTs. This
/// function takes an element in the plaintext space and must produce another
/// element in the plaintext space.
///
/// # Remarks
/// This function supports multiple functions, which appear as adjacent
/// entries in the ciphertext (padded with 0 up to a power of 2). This
/// pattern repeats until `n/p` terms have been filled.
pub(crate) fn generate_lut<S, F>(
    output: &mut PolynomialRef<Torus<S>>,
    maps: &[F],
    params: &GlweDef,
    plaintext_bits: PlaintextBits,
) where
    S: TorusOps,
    F: Fn(u64) -> u64,
{
    let p = (1 << plaintext_bits.0) as usize;
    let n = params.dim.polynomial_degree.0;

    let v = maps.len();

    let log_v = if v.is_power_of_two() {
        v.ilog2()
    } else {
        v.ilog2() + 1
    };

    let ceil_v = 0x1usize << log_v;

    assert!(n >= p);

    let stride = n / p;

    let delta = S::BITS - plaintext_bits.0;

    let c = output.coeffs_mut();

    for (j, p_i_unmapped) in (0..=p - 1).enumerate() {
        // Insert a stride amount into the LUT
        c[j * stride..(j + 1) * stride].iter_mut().enumerate().for_each(|(k, c)| {
            let fn_id = k % ceil_v;

            let p_i = if fn_id < v {
                maps[fn_id](p_i_unmapped as u64)
            } else {
                0u64
            };

            assert!(p_i < (p as u64), "The map function must produce a value less than p. Map produced the relation ({p_i_unmapped} -> {p_i})");

            let p_i = p_i << delta;

            *c = Torus::from(S::from_u64(p_i));
        });
    }

    // Negate the first half of p_0 in the LUT in preparation for it to be
    // rotated.
    c[0..stride / 2].iter_mut().for_each(|c| {
        *c = num::traits::WrappingNeg::wrapping_neg(c);
    });

    c.rotate_left(stride / 2);
}

#[allow(clippy::too_many_arguments)]
/// Programmable bootstrapping with a univariate function.
///
/// The LUT this is a table that maps two inputs into a single output.  For
/// example, say we want to encode the negation function `f(x) = (x + 1) % 2`
/// into a lookup table. We would create a
/// [`UnivariateLookupTable`](crate::entities::UnivariateLookupTable) that
/// implements this function and then execute it on the input ciphertexts.
///
/// Important note: This function does not perform key switching. The output
/// ciphertext will be encrypted under the LWE key extracted from the GLWE
/// secret key used for the bootstrapping key. To perform a keyswitch, use
/// [`keyswitch_lwe_to_lwe`](crate::ops::keyswitch::lwe_keyswitch::keyswitch_lwe_to_lwe)
/// after the bootstrapping operation.
///
/// # Example
///
/// ```
/// use sunscreen_tfhe::{
///   high_level::{keygen, encryption, fft},
///   entities::{UnivariateLookupTable, LweCiphertext},
///   ops::bootstrapping::programmable_bootstrap_univariate,
///   params::{
///     AddendCount,
///     GLWE_1_2048_128,
///     LWE_512_128,
///     CarryBits,
///     PlaintextBits,
///     RadixDecomposition,
///     RadixCount,
///     RadixLog
///   },
/// };
///
/// // Parameters defining the scheme we are using
/// let lwe_params = LWE_512_128;
/// let glwe_params = GLWE_1_2048_128;
/// let radix = RadixDecomposition {
///     count: RadixCount(3),
///     radix_log: RadixLog(4),
/// };
/// let addend_count = AddendCount(1);
///
/// // We will be showing a binary univariate function. Note that for
/// // programmable bootstrapping to work in general, you will need to include at
/// // least one padding bit to the input.
/// let plaintext_bits = PlaintextBits(1);
/// let carry_bits = CarryBits(1);
/// let plaintext_bits_carry = PlaintextBits(2);
///
/// // The univariate function we want to evaluate, encoded as a lookup table.
/// let negate = |x| (x + 1) % (1 << plaintext_bits.0);
/// let lut = UnivariateLookupTable::trivial_from_fn(
///     &negate,
///     &glwe_params,
///     plaintext_bits,
/// );
///
/// // Generate the secret keys and the bootstrapping key
/// let lwe_sk = keygen::generate_binary_lwe_sk(&lwe_params);
/// let glwe_sk = keygen::generate_binary_glwe_sk(&glwe_params);
///
/// let bsk = keygen::generate_bootstrapping_key(&lwe_sk, &glwe_sk, &lwe_params, &glwe_params, &radix, addend_count);
/// let bsk =
/// fft::fft_bootstrap_key(&bsk, &lwe_params, &glwe_params, &radix, addend_count);
///
/// // Specify the inputs
/// let input_plain = 0;
///
/// // Encrypt the inputs. Note we are adding carry bits to the inputs.
/// let input = encryption::encrypt_lwe_secret(
///     input_plain,
///     &lwe_sk,
///     &lwe_params,
///     plaintext_bits_carry
/// );
///
/// // Perform the programmable bootstrapping
/// let mut result = LweCiphertext::new(&glwe_params.as_lwe_def());
/// programmable_bootstrap_univariate(
///     &mut result,
///     &input,
///     &lut,
///     &bsk,
///     &lwe_params,
///     &glwe_params,
///     &radix,
///     addend_count
/// );
///
/// // Check the result matches our plaintext function.
/// let decrypted = encryption::decrypt_lwe(
///     &result,
///     &glwe_sk.to_lwe_secret_key(),
///     &glwe_params.as_lwe_def(),
///     plaintext_bits,
/// );
///
/// let expected = negate(input_plain);
/// assert_eq!(expected, decrypted);
/// ```
///
/// # See also
///
/// For the bivariate version of programmable bootstrapping, see
/// [`programmable_bootstrap_bivariate`](programmable_bootstrap_bivariate) and
/// its associated LUT
/// [`BivariateLookupTable`](crate::entities::BivariateLookupTable).
pub fn programmable_bootstrap_univariate<S>(
    output: &mut LweCiphertextRef<S>,
    input: &LweCiphertextRef<S>,
    lut: &UnivariateLookupTableRef<S>,
    bootstrap_key: &BootstrapKeyFftRef<Complex<f64>>,
    lwe_params: &LweDef,
    glwe_params: &GlweDef,
    radix: &RadixDecomposition,
    addend_count: AddendCount,
) where
    S: TorusOps,
{
    allocate_scratch_ref!(glwe, GlweCiphertextRef<S>, (glwe_params.dim));

    generalized_programmable_bootstrap(
        glwe,
        input,
        lut,
        bootstrap_key,
        0,
        0,
        lwe_params,
        glwe_params,
        radix,
        addend_count,
    );

    // 3. Sample extract.
    sample_extract(output, glwe, 0, glwe_params);
}

#[allow(clippy::too_many_arguments)]
/// A generalized version of programmable bootstrapping.
/// Computes a function `lut` of the encrypted `input`.
/// However, this generalization features the ability to select which
/// bits to take during modulus switching. This capability enables
/// encoding multiple functions into `lut` and bootstrapping each of them
/// simultaneously.
///
/// # Remarks
/// While [`programmable_bootstrap_univariate`] and
/// [`programmable_bootstrap_bivariate`] compute a single function of the
/// input ciphertext, this can compute multiple functions. To do this,
/// create a [`UnivariateLookupTable`](crate::entities::UnivariateLookupTable) using
/// [`UnivariateLookupTable::trivivial_multifunctional`](crate::entities::UnivariateLookupTable::trivivial_multifunctional).
///
/// `log_v` should equal `ceil(log2(maps.len()))` for the `maps` you
/// used when creating the LUT.
///
/// `log_chi` is the number of most-significant bits to drop during
/// bootstrapping. Generally, you should set this to zero unless building
/// other cryptographic primitives, such as Without Padding Bootstrapping
/// (WoP-PBS)
pub fn generalized_programmable_bootstrap<S>(
    output: &mut GlweCiphertextRef<S>,
    input: &LweCiphertextRef<S>,
    lut: &UnivariateLookupTableRef<S>,
    bootstrap_key: &BootstrapKeyFftRef<Complex<f64>>,
    log_chi: u32,
    log_v: u32,
    lwe_params: &LweDef,
    glwe_params: &GlweDef,
    radix: &RadixDecomposition,
    addend_count: AddendCount,
) where
    S: TorusOps,
{
    lwe_params.assert_valid();
    glwe_params.assert_valid();
    radix.assert_valid::<S>();
    bootstrap_key.assert_is_valid((lwe_params.dim, glwe_params.dim, radix.count, addend_count));
    lut.assert_is_valid(glwe_params.dim);
    input.assert_is_valid(lwe_params.dim);
    output.assert_is_valid(glwe_params.dim);
    addend_count.assert_valid();

    // Steps:
    // 1. Modulus switch the ciphertext to 2N.
    // 2. Blind rotate V using the elements of the bootstrap key (the input LWE secret key bits). The algorithm for this depends on addend_count.
    // 3. Sample extract.
    // 4. (Optional, done outside of this method) Key switch to the output LWE
    // secret key (should be the one extracted from the GLWE key).

    let degree = glwe_params.dim.polynomial_degree.0;
    let two_n = degree.ilog2() + 1;

    // 1. Modulus switch the ciphertext to 2N.
    let mut ct = input.to_owned();
    lwe_ciphertext_modulus_switch(&mut ct, log_chi, log_v, two_n, lwe_params);

    let (_, ct_b) = ct.a_b(lwe_params);

    // Perform V_0 ^ X^{-b}
    output.clear();

    rotate_glwe_negative_monomial_negacyclic(
        output,
        lut.glwe(),
        ct_b.inner().to_u64() as usize,
        glwe_params,
    );

    apply_blind_rotations(
        output,
        &ct,
        bootstrap_key,
        lwe_params,
        glwe_params,
        radix,
        addend_count,
    );
}

#[inline(always)]
fn apply_blind_rotations<S>(
    accumulator: &mut GlweCiphertextRef<S>,
    mod_switched_lwe: &LweCiphertextRef<S>,
    bootstrap_key: &BootstrapKeyFftRef<Complex<f64>>,
    lwe_params: &LweDef,
    glwe_params: &GlweDef,
    radix: &RadixDecomposition,
    addend_count: AddendCount,
) where
    S: TorusOps,
{
    let (ct_a, _) = mod_switched_lwe.a_b(lwe_params);

    let bundle_size = bootstrap_key_bundle_size(addend_count);

    // Perform the cmux tree from the bootstrap key with the relation
    // V_n = V_{n-1} ^ X^{a_{n-1} s_{n-1}}

    // Do the body of work that cleanly divides the addend count.
    for i in 0..lwe_params.dim.0 / addend_count.0 as usize {
        let a_i = ct_a
            .iter()
            .skip(i * addend_count.0 as usize)
            .take(addend_count.0 as usize);
        let bsk_bundle = bootstrap_key
            .rows(glwe_params, radix)
            .skip(i * bundle_size)
            .take(bundle_size);

        apply_addends(
            accumulator,
            a_i,
            bsk_bundle,
            glwe_params,
            radix,
            addend_count,
        );
    }

    let remainder = lwe_params.dim.0 % addend_count.0 as usize;

    // Handle the remaining elements.
    if remainder > 0 {
        let skip = lwe_params.dim.0 / addend_count.0 as usize;

        let a_i = ct_a.iter().skip(skip * addend_count.0 as usize);
        let bsk_bundle = bootstrap_key
            .rows(glwe_params, radix)
            .skip(skip * bundle_size);

        apply_addends(
            accumulator,
            a_i,
            bsk_bundle,
            glwe_params,
            radix,
            AddendCount(remainder as u32),
        );
    }
}

/// Applies a single set of blind rotations using a bundle of bootstrap key elements,
/// and the corresponding a_i terms.
///
/// # Remarks
/// When addend count is 1, this applies the standard CMUX operations given in the original
/// CGGI16 TFHE paper. When rotating 2 or 3 bits at a time, computes a GGSW keybundle and
/// performs an outer product as described in ZYLL18.
#[inline(always)]
fn apply_addends<'a, IA, IBSK, S>(
    accumulator: &mut GlweCiphertextRef<S>,
    mut a: IA,
    mut bsk_bundle: IBSK,
    glwe_params: &GlweDef,
    radix: &RadixDecomposition,
    addend_count: AddendCount,
) where
    IA: Iterator<Item = &'a Torus<S>> + 'a,
    IBSK: Iterator<Item = &'a GgswCiphertextFftRef<Complex<f64>>> + 'a,
    S: TorusOps,
{
    if addend_count.0 == 1 {
        allocate_scratch_ref!(rotated_ct, GlweCiphertextRef<S>, (glwe_params.dim));
        let accumulator_clone = accumulator.to_owned();

        // This operation performs a copy so the rotated_ct doesn't need to be
        // cleared.
        rotate_glwe_positive_monomial_negacyclic(
            rotated_ct,
            accumulator,
            a.next().unwrap().to_u64() as usize,
            glwe_params,
        );

        cmux(
            accumulator,
            &accumulator_clone,
            rotated_ct,
            bsk_bundle.next().unwrap(),
            glwe_params,
            radix,
        );

        assert!(bsk_bundle.next().is_none());
        assert!(a.next().is_none());
    } else if addend_count.0 == 2 {
        let a_i_min_1 = a.next().unwrap().to_u64() as usize;
        let a_i = a.next().unwrap().to_u64() as usize;
        assert!(a.next().is_none());

        allocate_scratch_ref!(
            result,
            GlweCiphertextFftRef<Complex<f64>>,
            (glwe_params.dim)
        );
        allocate_scratch_ref!(
            prod,
            GgswCiphertextFftRef<Complex<f64>>,
            (glwe_params.dim, radix.count)
        );
        allocate_scratch_ref!(
            sum_addends,
            GgswCiphertextFftRef<Complex<f64>>,
            (glwe_params.dim, radix.count)
        );

        // (s_i - 1)(s_(i - 1) - 1)
        sum_addends.clone_from_ref(bsk_bundle.next().unwrap());

        // a_(i - 1)(s_i - 1)(s_(i - 1))
        mul_ggsw_ciphertext_positive_monomial_fft(
            prod,
            bsk_bundle.next().unwrap(),
            a_i_min_1,
            glwe_params,
            radix,
        );
        sub_assign_ggsw_ciphertexts_fft(sum_addends, prod, glwe_params, radix);

        // a_i(s_i)(s_(i - 1) - 1)
        mul_ggsw_ciphertext_positive_monomial_fft(
            prod,
            bsk_bundle.next().unwrap(),
            a_i,
            glwe_params,
            radix,
        );
        sub_assign_ggsw_ciphertexts_fft(sum_addends, prod, glwe_params, radix);

        // a_i * a_(i - 1)(s_i)(s_(i - 1))
        mul_ggsw_ciphertext_positive_monomial_fft(
            prod,
            bsk_bundle.next().unwrap(),
            a_i + a_i_min_1,
            glwe_params,
            radix,
        );
        add_assign_ggsw_ciphertexts_fft(sum_addends, prod, glwe_params, radix);

        assert!(bsk_bundle.next().is_none());

        result.clear();

        // acc *= sum_addends
        glwe_ggsw_mad(result, accumulator, &sum_addends, glwe_params, radix);

        result.ifft(accumulator, glwe_params);
    } else if addend_count.0 == 3 {
        todo!("Need to finish 3 addends algo");
    }
}

/// Evaluate a bivariate function on a packed input.
fn bivariate_function<F>(map: F, input: u64, plaintext_bits: PlaintextBits) -> u64
where
    F: Fn(u64, u64) -> u64,
{
    let modulus = 1 << plaintext_bits.0;
    let lhs = (input / modulus) % modulus;
    let rhs = input % modulus;

    let result = map(lhs, rhs);

    assert!(
        result < modulus,
        "The result of the bivariate function must be less than the plaintext modulus"
    );

    result
}

/// Generate a lookup table that takes two inputs and produces a single output.
pub(crate) fn generate_bivariate_lut<S, F>(
    output: &mut PolynomialRef<Torus<S>>,
    map: F,
    params: &GlweDef,
    plaintext_bits: PlaintextBits,
    carry_bits: CarryBits,
) where
    S: TorusOps,
    F: Fn(u64, u64) -> u64,
{
    assert!(
        plaintext_bits.0 <= carry_bits.0,
        "The number of plaintext bits must be less than or equal to the number of carry bits"
    );

    let wrapped_func = |input: u64| bivariate_function(&map, input, plaintext_bits);

    generate_lut(
        output,
        &[wrapped_func],
        params,
        PlaintextBits(plaintext_bits.0 + carry_bits.0),
    );
}

/// Programmable bootstrapping with a bivariate function.
///
/// The LUT this is a table that maps two inputs into a single output.
/// For example, say we want to encode the xor function `f(x, y) = (x + y) % 2`
/// into a lookup table. We would create a
/// [`BivariateLookupTable`](crate::entities::BivariateLookupTable) that
/// implements this function and then execute it on the input ciphertexts.
///
/// Important note: This function does not perform key switching. The output
/// ciphertext will be encrypted under the LWE key extracted from the GLWE
/// secret key used for the bootstrapping key. To perform a keyswitch, use
/// [`keyswitch_lwe_to_lwe`](crate::ops::keyswitch::lwe_keyswitch::keyswitch_lwe_to_lwe)
/// after the bootstrapping operation.
///
/// # Example
///
/// ```
/// use sunscreen_tfhe::{
///   high_level::{keygen, encryption, fft},
///   entities::{BivariateLookupTable, LweCiphertext},
///   ops::bootstrapping::programmable_bootstrap_bivariate,
///   params::{
///     AddendCount,
///     GLWE_1_2048_128,
///     LWE_512_128,
///     CarryBits,
///     PlaintextBits,
///     RadixDecomposition,
///     RadixCount,
///     RadixLog
///   },
/// };
///
/// // Parameters defining the scheme we are using
/// let lwe_params = LWE_512_128;
/// let glwe_params = GLWE_1_2048_128;
/// let radix = RadixDecomposition {
///     count: RadixCount(3),
///     radix_log: RadixLog(4),
/// };
/// let addend_count = AddendCount(1);
///
/// // We will be showing a binary bivariate function, but bivariate
/// // bootstrapping can be done on more plaintext bits. Note that the effective
/// // number of plaintext bits used is twice the number of plaintext bits
/// // specified because the inputs are packed into one ciphertext inside
/// // `programmable_bootstrap_bivariate`. The number of carry bits must always
/// // be greater than or equal to the number of plaintext bits.
/// let plaintext_bits = PlaintextBits(1);
/// let plaintext_bits_carry = PlaintextBits(2);
/// let carry_bits = CarryBits(1);
///
/// // The bivariate function we want to evaluate, encoded as a lookup table.
/// let xor = |x, y| (x + y) % (1 << plaintext_bits.0);
/// let lut = BivariateLookupTable::trivial_from_fn(
///     &xor,
///     &glwe_params,
///     plaintext_bits,
///     carry_bits
/// );
///
/// // Generate the secret keys and the bootstrapping key
/// let lwe_sk = keygen::generate_binary_lwe_sk(&lwe_params);
/// let glwe_sk = keygen::generate_binary_glwe_sk(&glwe_params);
///
/// let bsk = keygen::generate_bootstrapping_key(&lwe_sk, &glwe_sk, &lwe_params, &glwe_params, &radix, addend_count);
/// let bsk =
/// fft::fft_bootstrap_key(&bsk, &lwe_params, &glwe_params, &radix, addend_count);
///
/// // Specify the inputs
/// let left_input_plain = 0;
/// let right_input_plain = 1;
///
/// // Encrypt the inputs. Note we are adding carry bits to the inputs.
/// let left_input = encryption::encrypt_lwe_secret(
///     left_input_plain,
///     &lwe_sk,
///     &lwe_params,
///     plaintext_bits_carry
/// );
/// let right_input = encryption::encrypt_lwe_secret(
///     right_input_plain,
///     &lwe_sk,
///     &lwe_params,
///     plaintext_bits_carry
/// );
///
/// // Perform the programmable bootstrapping
/// let mut result = LweCiphertext::new(&glwe_params.as_lwe_def());
/// programmable_bootstrap_bivariate(
///     &mut result,
///     &left_input,
///     &right_input,
///     &lut,
///     &bsk,
///     &lwe_params,
///     &glwe_params,
///     plaintext_bits,
///     &radix,
///     addend_count
/// );
///
/// // Check the result matches our plaintext function.
/// let decrypted = encryption::decrypt_lwe_with_carry(
///     &result,
///     &glwe_sk.to_lwe_secret_key(),
///     &glwe_params.as_lwe_def(),
///     plaintext_bits,
///     carry_bits
/// );
///
/// let expected = xor(left_input_plain, right_input_plain);
/// assert_eq!(expected, decrypted);
/// ```
///
/// # See also
///
/// For the univariate version of programmable bootstrapping, see
/// [`programmable_bootstrap_univariate`](programmable_bootstrap_univariate) and its associated LUT
/// [`UnivariateLookupTable`](crate::entities::UnivariateLookupTable).
#[allow(clippy::too_many_arguments)]
pub fn programmable_bootstrap_bivariate<S>(
    output: &mut LweCiphertextRef<S>,
    left_input: &LweCiphertextRef<S>,
    right_input: &LweCiphertextRef<S>,
    lut: &BivariateLookupTableRef<S>,
    bootstrap_key: &BootstrapKeyFftRef<Complex<f64>>,
    lwe_params: &LweDef,
    glwe_params: &GlweDef,
    plaintext_bits: PlaintextBits,
    radix: &RadixDecomposition,
    addend_count: AddendCount,
) where
    S: TorusOps,
{
    // The general operation for a bivariate PBS is
    //
    // 1. Ensure that the number of carry bits is equal to the size of the
    //    message or greater.
    // 2. Define a LUT where the function takes in one input and decomposes that
    //    input into the higher n plaintext and lower n plaintext bits. The
    //    higher n bits are the left input to the bivariate function, while the
    //    lower n bits are the right input to the bivariate function.
    // 3. Encrypt the two input ciphertexts using the number of carry bits and
    //    the plaintext bits, with padding.
    // 4. On the left encrypted input, shift it up by the number of plaintext
    //    bits by multiplying the ciphertext by the plaintext modulus.
    // 5. Add the left and right encrypted inputs together.
    // 6. Perform the programmable bootstrapping with this combined input.

    let shift = (1 << plaintext_bits.0) as u64;

    allocate_scratch_ref!(pbs_input, LweCiphertextRef<S>, (lwe_params.dim));
    pbs_input.clear();

    // (left * modulus) + right to pack the two inputs into a single LWE
    scalar_mul_ciphertext_mad(pbs_input, &S::from_u64(shift), left_input, lwe_params);
    add_lwe_inplace(pbs_input, right_input, lwe_params);

    programmable_bootstrap_univariate(
        output,
        pbs_input,
        lut.as_univariate(),
        bootstrap_key,
        lwe_params,
        glwe_params,
        radix,
        addend_count,
    )
}

#[cfg(test)]
mod tests {

    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::{
        AddendCount, GLWE_1_2048_128, LWE_637_128, LweDimension, RadixCount, RadixLog, RoundedDiv,
        entities::{
            BivariateLookupTable, BootstrapKey, BootstrapKeyFft, GlweCiphertext, LweCiphertext,
            LweKeyswitchKey, UnivariateLookupTable,
        },
        high_level::{TEST_GLWE_DEF_1, TEST_LWE_DEF_1, TEST_RADIX, encryption, fft, keygen},
        ops::{
            encryption::{decrypt_ggsw_ciphertext, encrypt_lwe_ciphertext},
            keyswitch::lwe_keyswitch_key::generate_keyswitch_key_lwe,
        },
        rand::Stddev,
    };

    use super::*;

    fn generate_negacyclic_lut_from_formula<S>(
        params: &GlweDef,
        plaintext_bits: PlaintextBits,
    ) -> Polynomial<Torus<S>>
    where
        S: TorusOps,
    {
        let mut output = Polynomial::<Torus<S>>::zero(params.dim.polynomial_degree.0);

        let p = (1 << plaintext_bits.0) as u64;
        let n = params.dim.polynomial_degree.0 as u64;

        let divisor = 2 * n;

        for (j, c) in output.coeffs_mut().iter_mut().enumerate() {
            let v_i = ((p * (j as u64)).div_rounded(divisor)) % p;
            let v_i = v_i << (S::BITS - plaintext_bits.0);
            *c = Torus::from(S::from_u64(v_i));
        }

        output
    }

    #[test]
    fn can_generate_negacyclic_lut() {
        let p = PlaintextBits(4);
        let params = TEST_GLWE_DEF_1;

        let mut poly = Polynomial::<Torus<u64>>::zero(params.dim.polynomial_degree.0);
        generate_negacyclic_lut(&mut poly, |x| x, &params, p);

        let expected = generate_negacyclic_lut_from_formula(&params, p);

        assert_eq!(expected, poly);
    }

    #[test]
    fn can_generate_bootstrap_key() {
        let lwe_params = TEST_LWE_DEF_1;
        let glwe_params = TEST_GLWE_DEF_1;
        let radix = TEST_RADIX;
        let addend_count = AddendCount(1);

        let sk = keygen::generate_binary_lwe_sk(&lwe_params);
        let glwe_sk = keygen::generate_binary_glwe_sk(&glwe_params);

        let mut bootstrap_key = BootstrapKey::new(&lwe_params, &glwe_params, &radix, addend_count);
        generate_bootstrap_key(
            &mut bootstrap_key,
            &sk,
            &glwe_sk,
            &lwe_params,
            &glwe_params,
            &radix,
            addend_count,
        );

        let mut count = 0;
        for (s_i, ct) in sk.s().iter().zip(bootstrap_key.rows(&glwe_params, &radix)) {
            let mut msg = Polynomial::<Torus<u64>>::zero(glwe_params.dim.polynomial_degree.0);
            decrypt_ggsw_ciphertext(&mut msg, ct, &glwe_sk, &glwe_params, &radix);

            assert_eq!(msg.coeffs()[0].inner(), *s_i);

            count += 1
        }

        assert_eq!(count, sk.s().len());
    }

    fn bootstrap_helper(map: impl Fn(u64) -> u64) {
        let bits = PlaintextBits(3);
        let lwe = LWE_637_128;
        let glwe = GLWE_1_2048_128;
        let radix = RadixDecomposition {
            count: RadixCount(2),
            radix_log: RadixLog(16),
        };
        let addend_count = AddendCount(1);

        let original_sk = keygen::generate_binary_lwe_sk(&lwe);
        let glwe_sk = keygen::generate_binary_glwe_sk(&glwe);

        // We want to switch from the sample extracted key to the new key.
        let mut ksk = LweKeyswitchKey::<u64>::new(&glwe.as_lwe_def(), &lwe, &radix);
        generate_keyswitch_key_lwe(
            &mut ksk,
            glwe_sk.to_lwe_secret_key(),
            &original_sk,
            &glwe.as_lwe_def(),
            &lwe,
            &radix,
        );

        let mut bsk_nonfft = BootstrapKey::new(&lwe, &glwe, &radix, addend_count);
        generate_bootstrap_key(
            &mut bsk_nonfft,
            &original_sk,
            &glwe_sk,
            &lwe,
            &glwe,
            &radix,
            addend_count,
        );

        let mut bsk = BootstrapKeyFft::new(&lwe, &glwe, &radix, addend_count);
        bsk_nonfft.fft(&mut bsk, &lwe, &glwe, &radix, addend_count);

        // Generate the LUT
        let lut = UnivariateLookupTable::trivial_from_fn(&map, &glwe, bits);

        let mut failed = Vec::new();
        for msg in 0..(1 << bits.0) {
            let mut original_ct = LweCiphertext::new(&lwe);

            // Adding a padding bit
            let encoded_msg = msg << (64 - bits.0 - 1);
            encrypt_lwe_ciphertext(
                &mut original_ct,
                &original_sk,
                Torus::from(encoded_msg),
                &lwe,
            );

            let mut new_ct = LweCiphertext::new(&glwe.as_lwe_def());

            programmable_bootstrap_univariate(
                &mut new_ct,
                &original_ct,
                &lut,
                &bsk,
                &lwe,
                &glwe,
                &radix,
                addend_count,
            );

            let decoded = glwe_sk
                .to_lwe_secret_key()
                .decrypt(&new_ct, &glwe.as_lwe_def(), bits);

            let result = map(msg);
            if result != decoded {
                failed.push((result, decoded));
            }
        }

        if !failed.is_empty() {
            panic!("Failed to decrypt the following messages and decrypted values: {failed:?}");
        }
    }

    #[test]
    fn can_bootstrap() {
        bootstrap_helper(|x| x);
    }

    #[test]
    fn can_bootstrap_with_map() {
        bootstrap_helper(|x| (x + 3) % 8);
    }

    fn bivariate_bootstrap_helper(map: impl Fn(u64, u64) -> u64) {
        let lwe = TEST_LWE_DEF_1;
        let glwe = TEST_GLWE_DEF_1;
        let _radix = TEST_RADIX;
        let bits = PlaintextBits(1);

        let carry_bits = CarryBits(1);
        let radix = TEST_RADIX;
        let addend_count = AddendCount(1);

        let original_sk = keygen::generate_binary_lwe_sk(&lwe);
        let glwe_sk = keygen::generate_binary_glwe_sk(&glwe);

        // We want to switch from the sample extracted key to the new key.
        let mut ksk = LweKeyswitchKey::<u64>::new(&glwe.as_lwe_def(), &lwe, &radix);
        generate_keyswitch_key_lwe(
            &mut ksk,
            glwe_sk.to_lwe_secret_key(),
            &original_sk,
            &glwe.as_lwe_def(),
            &lwe,
            &radix,
        );

        let mut bsk_nonfft = BootstrapKey::new(&lwe, &glwe, &radix, addend_count);
        generate_bootstrap_key(
            &mut bsk_nonfft,
            &original_sk,
            &glwe_sk,
            &lwe,
            &glwe,
            &radix,
            addend_count,
        );

        let mut bsk = BootstrapKeyFft::new(&lwe, &glwe, &radix, addend_count);
        bsk_nonfft.fft(&mut bsk, &lwe, &glwe, &radix, addend_count);

        // Generate the LUT
        let lut = BivariateLookupTable::trivial_from_fn(&map, &glwe, bits, carry_bits);

        let mut failed = Vec::new();
        let mut succeeded = Vec::new();

        for left_msg in 0..(1 << bits.0) {
            for right_msg in 0..(1 << bits.0) {
                let mut left_ct = LweCiphertext::new(&lwe);
                let mut right_ct = LweCiphertext::new(&lwe);

                // Adding a padding bit, hence the - 1
                let encoded_left_msg = left_msg << (64 - bits.0 - carry_bits.0 - 1);
                let encoded_right_msg = right_msg << (64 - bits.0 - carry_bits.0 - 1);

                encrypt_lwe_ciphertext(
                    &mut left_ct,
                    &original_sk,
                    Torus::from(encoded_left_msg),
                    &lwe,
                );

                encrypt_lwe_ciphertext(
                    &mut right_ct,
                    &original_sk,
                    Torus::from(encoded_right_msg),
                    &lwe,
                );

                let mut new_ct = LweCiphertext::new(&glwe.as_lwe_def());

                programmable_bootstrap_bivariate(
                    &mut new_ct,
                    &left_ct,
                    &right_ct,
                    &lut,
                    &bsk,
                    &lwe,
                    &glwe,
                    bits,
                    &radix,
                    addend_count,
                );

                let decrypted = glwe_sk
                    .to_lwe_secret_key()
                    .decrypt_without_decode(&new_ct, &glwe.as_lwe_def());

                // We manually decode here because the
                let plain_bits = bits;

                let round_bit = decrypted
                    .inner()
                    .wrapping_shr(64 - plain_bits.0 - carry_bits.0 - 1)
                    & 0x1;
                let mask = (0x1 << plain_bits.0) - 1;

                let decoded = (decrypted
                    .inner()
                    .wrapping_shr(64 - plain_bits.0 - carry_bits.0)
                    + round_bit)
                    & mask;

                let result = map(left_msg, right_msg);
                if result != decoded {
                    failed.push(((left_msg, right_msg), result, decoded));
                } else {
                    succeeded.push(((left_msg, right_msg), result, decoded));
                }
            }
        }
        if !failed.is_empty() {
            panic!(
                "Failed to decrypt the following messages and decrypted values (as ((left input, right_input), expected, decrypted)): {failed:?}. However, the following messages and decrypted values succeeded: {succeeded:?}"
            );
        }
    }

    fn bivariate_test_function(left: u64, right: u64) -> u64 {
        (left + right) % 2
    }

    #[test]
    fn can_bootstrap_with_bivariate_map() {
        bivariate_bootstrap_helper(bivariate_test_function);
    }

    #[test]
    fn can_decompose_bivariate_map() {
        let plaintext_bits = PlaintextBits(2);
        let modulus = 1 << plaintext_bits.0;

        let map = &bivariate_test_function;

        for left in 0u64..(plaintext_bits.0 as u64) {
            for right in 0u64..(plaintext_bits.0 as u64) {
                let left_shifted = left * modulus;
                let input = left_shifted + right;
                let result = bivariate_function(map, input, plaintext_bits);

                assert_eq!(result, map(left, right));
            }
        }
    }

    fn generalized_bootstrap_case(addend_count: AddendCount) {
        let radix = &TEST_RADIX;
        let lwe = &LWE_637_128;
        let glwe = &GLWE_1_2048_128;

        // 1 message bit + 1 padding
        let bits = PlaintextBits(1);

        let lwe_sk = keygen::generate_binary_lwe_sk(lwe);
        let glwe_sk = keygen::generate_binary_glwe_sk(glwe);
        let bs_key =
            keygen::generate_bootstrapping_key(&lwe_sk, &glwe_sk, lwe, glwe, radix, addend_count);
        let bs_key = fft::fft_bootstrap_key(&bs_key, lwe, glwe, radix, addend_count);

        // Fill the LUT with nonsense and we'll overwrite it with
        // the correct encoding.
        let lut = UnivariateLookupTable::trivivial_multifunctional(
            [|x| x % 2, |x| (x + 1) % 2, |x| x % 2].as_slice(),
            glwe,
            bits,
        );

        for i in [0, 1] {
            //let input = encryption::encrypt_lwe_secret(i, &lwe_sk, lwe, bits);
            let input = encryption::trivial_lwe(i, lwe, PlaintextBits(2));
            let mut output = GlweCiphertext::new(glwe);

            generalized_programmable_bootstrap(
                &mut output,
                &input,
                &lut,
                &bs_key,
                0,
                3,
                lwe,
                glwe,
                radix,
                addend_count,
            );

            let res = encryption::decrypt_glwe(&output, &glwe_sk, glwe, bits);

            if i == 0 {
                assert_eq!(res.coeffs()[0], 0);
                assert_eq!(res.coeffs()[1], 1);
                assert_eq!(res.coeffs()[2], 0);
                assert_eq!(res.coeffs()[3], 0);
                assert_eq!(res.coeffs()[4], 0);
                assert_eq!(res.coeffs()[5], 1);
                assert_eq!(res.coeffs()[6], 0);
                assert_eq!(res.coeffs()[7], 0);
            } else {
                assert_eq!(res.coeffs()[0], 1);
                assert_eq!(res.coeffs()[1], 0);
                assert_eq!(res.coeffs()[2], 1);
                assert_eq!(res.coeffs()[3], 0);
                assert_eq!(res.coeffs()[4], 1);
                assert_eq!(res.coeffs()[5], 0);
                assert_eq!(res.coeffs()[6], 1);
                assert_eq!(res.coeffs()[7], 0);
            }
        }
    }

    #[test]
    fn can_generalized_bootstrap() {
        generalized_bootstrap_case(AddendCount(1));
    }

    #[test]
    fn can_generalized_bootstrap_2_addends() {
        generalized_bootstrap_case(AddendCount(2));
    }

    #[test]
    fn bsk_len_vs_addends() {
        let lwe = LweDef {
            dim: LweDimension(131),
            std: Stddev(1e-16),
        };
        let glwe = TEST_GLWE_DEF_1;
        let radix = TEST_RADIX;

        let bootstrap_key = BootstrapKey::<u64>::new(&lwe, &glwe, &radix, AddendCount(1));

        assert_eq!(bootstrap_key.rows(&glwe, &radix).len(), lwe.dim.0);

        let bootstrap_key = BootstrapKey::<u64>::new(&lwe, &glwe, &radix, AddendCount(2));

        // 4 elements for the first 130 / 2 elements + 1 for the leftover
        assert_eq!(bootstrap_key.rows(&glwe, &radix).len(), 65 * 4 + 1);

        let bootstrap_key = BootstrapKey::<u64>::new(&lwe, &glwe, &radix, AddendCount(3));

        // 8 elements for the first 130 / 3 elements + 4 for the remaining 2 elements
        assert_eq!(bootstrap_key.rows(&glwe, &radix).len(), 43 * 8 + 4);
    }

    #[test]
    fn can_generate_bsk_multiple_addends() {
        for addend_count in [AddendCount(2), AddendCount(3)] {
            // Use a value that isn't a multiple of the addend count.
            let lwe_params = LweDef {
                dim: LweDimension(131),
                std: Stddev(1e-16),
            };
            let glwe_params = TEST_GLWE_DEF_1;
            let radix = TEST_RADIX;

            let sk = keygen::generate_binary_lwe_sk(&lwe_params);
            let glwe_sk = keygen::generate_binary_glwe_sk(&glwe_params);

            let mut bootstrap_key =
                BootstrapKey::new(&lwe_params, &glwe_params, &radix, addend_count);
            generate_bootstrap_key(
                &mut bootstrap_key,
                &sk,
                &glwe_sk,
                &lwe_params,
                &glwe_params,
                &radix,
                addend_count,
            );

            let actual_keybundles = AtomicUsize::new(0);
            sk.s()
                .par_chunks(addend_count.0 as usize)
                .zip(
                    bootstrap_key
                        .rows_par(&glwe_params, &radix)
                        .chunks(bootstrap_key_bundle_size(addend_count)),
                )
                .enumerate()
                .for_each(|(bid, (s_i, ct))| {
                    let bs = bootstrap_key_bundle_size(AddendCount(s_i.len() as u32));
                    assert_eq!(bs, ct.len());

                    // If the current bundle has more than one element in it, assert
                    // each key in the bundle encrypts the appropriate sum-of-products
                    // term of the orginal key.
                    if s_i.len() > 1 {
                        let mut num_ones = 0;

                        #[allow(clippy::needless_range_loop)]
                        for i in 0..bs {
                            let expected = s_i
                                .iter()
                                .enumerate()
                                .map(|(j, s_i)| {
                                    if (i >> j) & 0x1 == 1 {
                                        *s_i
                                    } else {
                                        !*s_i & 0x1
                                    }
                                })
                                .fold(1, |s, x| s & x);

                            let mut msg =
                                Polynomial::<Torus<u64>>::zero(glwe_params.dim.polynomial_degree.0);
                            decrypt_ggsw_ciphertext(
                                &mut msg,
                                ct[i],
                                &glwe_sk,
                                &glwe_params,
                                &radix,
                            );

                            assert_eq!(
                                msg.coeffs()[0].inner(),
                                expected,
                                "Bundle {bid}, ct {i}: actual {} does not match {expected}",
                                msg.coeffs()[0].inner()
                            );

                            if msg.coeffs()[0].inner() != 0 {
                                num_ones += 1;
                            }
                        }

                        // The product of exactly one of the addend terms should be 1.
                        assert_eq!(num_ones, 1);
                    } else {
                        let mut msg =
                            Polynomial::<Torus<u64>>::zero(glwe_params.dim.polynomial_degree.0);

                        // If the bundle *does* have only one element, it should just
                        // encrypt the corresponding term in s_i.
                        decrypt_ggsw_ciphertext(&mut msg, ct[0], &glwe_sk, &glwe_params, &radix);

                        assert_eq!(
                            msg.coeffs()[0].inner(),
                            s_i[0],
                            "Bundle {bid}, ct 0: actual {} does not match {}",
                            msg.coeffs()[0].inner(),
                            s_i[0]
                        );
                    }

                    actual_keybundles.fetch_add(1, Ordering::Relaxed);
                });

            let expected_keybundles = lwe_params.dim.0.next_multiple_of(addend_count.0 as usize)
                / addend_count.0 as usize;

            assert_eq!(
                actual_keybundles.load(Ordering::Relaxed),
                expected_keybundles
            );
        }
    }
}
