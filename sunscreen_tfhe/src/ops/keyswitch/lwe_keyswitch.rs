use crate::{
    LweDef, OverlaySize, PolynomialDegree, RadixDecomposition, Torus, TorusOps,
    dst::{FromMutSlice, FromSlice},
    entities::{LweCiphertext, LweCiphertextRef, LweKeyswitchKeyRef, PolynomialRef},
    ops::{
        ciphertext::{decomposed_scalar_lev_mad, sub_lwe_ciphertexts},
        encryption::trivially_encrypt_lwe_ciphertext,
    },
    radix::PolynomialRadixIterator,
    scratch::allocate_scratch_ref,
};

fn mean_compensate_pre_keyswitch_lwe_to_lwe<S: TorusOps>(
    output: &mut LweCiphertextRef<S>,
    input: &LweCiphertextRef<S>,
    params: &LweDef,
    radix: &RadixDecomposition,
) {
    input.assert_is_valid(params.dim);
    output.assert_is_valid(params.dim);

    let (input_a, input_b) = input.a_b(params);
    let (output_a, output_b) = output.a_b_mut(params);

    let bits_to_drop = S::BITS as usize - radix.count.0 * radix.radix_log.0;
    let carrier = <S as sunscreen_math::One>::one() << (bits_to_drop - 1);
    let mut cum_err = <S as sunscreen_math::Zero>::zero();

    for (i, o) in input_a.iter().zip(output_a.iter_mut()) {
        *o = Torus::from(i.wrapping_add(&carrier) >> bits_to_drop << bits_to_drop);
        cum_err = cum_err.wrapping_add(&i.wrapping_sub(&o));
    }

    // multiply `cum_err` by mean of secret key which is 1/2, so we implement right shift by 1
    // for this purpose, and note here `cum_err` must be interpreted as signed value so we mask
    // its MSB to add back later
    let cum_err_msb = cum_err & (<S as sunscreen_math::One>::one() << (S::BITS as usize - 1));
    cum_err = cum_err >> 1;
    cum_err |= cum_err_msb;

    *output_b = Torus::from(input_b.wrapping_sub(&cum_err));
}

/// Switches a ciphertext under the original key to a ciphertext under the new
/// key using a keyswitch key.
///
/// Arguments:
///
/// * output: the output ciphertext
/// * ciphertext_under_original_key: the input ciphertext
/// * keyswitch_key: the keyswitch key
/// * old_params: the parameters of the original ciphertext
/// * new_params: the parameters of the output ciphertext
pub fn keyswitch_lwe_to_lwe<S>(
    output: &mut LweCiphertextRef<S>,
    ciphertext_under_original_key: &LweCiphertextRef<S>,
    keyswitch_key: &LweKeyswitchKeyRef<S>,
    old_params: &LweDef,
    new_params: &LweDef,
    radix: &RadixDecomposition,
) where
    S: TorusOps,
{
    old_params.assert_valid();
    new_params.assert_valid();
    radix.assert_valid::<S>();
    output.assert_is_valid(new_params.dim);
    ciphertext_under_original_key.assert_is_valid(old_params.dim);
    keyswitch_key.assert_is_valid((old_params.dim, new_params.dim, radix.count));

    allocate_scratch_ref!(
        fixed_ciphertext_under_original_key,
        LweCiphertextRef<S>,
        (old_params.dim)
    );

    mean_compensate_pre_keyswitch_lwe_to_lwe(
        fixed_ciphertext_under_original_key,
        ciphertext_under_original_key,
        old_params,
        radix,
    );

    let (ciphertext_a, ciphertext_b) = fixed_ciphertext_under_original_key.a_b(old_params);

    let keyswitch_levs = keyswitch_key.rows(new_params, radix);

    let mut a_i_decomp_sum = LweCiphertext::new(new_params);

    allocate_scratch_ref!(scratch, PolynomialRef<S>, (PolynomialDegree(1)));

    // sum_i(<decomp(ciphertext_a_i), lev_i>)
    for (a_i, lev_i) in ciphertext_a.iter().zip(keyswitch_levs) {
        let decomp =
            PolynomialRadixIterator::new(PolynomialRef::from_slice(&[*a_i]), scratch, radix);

        decomposed_scalar_lev_mad(&mut a_i_decomp_sum, decomp, lev_i, new_params);
    }

    // trivial_encrypt(ciphertext_b)
    let mut trivial_b = LweCiphertext::new(new_params);
    trivially_encrypt_lwe_ciphertext(&mut trivial_b, ciphertext_b, new_params);

    // output = trivial_encrypt(ciphertext_b) - sum_i(<decomp(ciphertext_a_i), glev_i>)
    sub_lwe_ciphertexts(output, &trivial_b, &a_i_decomp_sum, new_params);
}

#[cfg(test)]
mod tests {

    use rand::{RngCore, rng};

    use crate::{PlaintextBits, high_level::*};

    #[test]
    fn keyswitch_lwe() {
        let bits = PlaintextBits(4);
        let from_lwe = TEST_LWE_DEF_1;
        let to_lwe = TEST_LWE_DEF_2;
        let radix = TEST_RADIX;

        for _ in 0..50 {
            let original_sk = keygen::generate_binary_lwe_sk(&from_lwe);
            let new_sk = keygen::generate_binary_lwe_sk(&to_lwe);

            let ksk = keygen::generate_ksk(&original_sk, &new_sk, &from_lwe, &to_lwe, &radix);

            let msg = rng().next_u64() % (1 << bits.0);

            let original_ct = original_sk.encrypt(msg, &from_lwe, bits).0;

            let new_ct =
                evaluation::keyswitch_lwe_to_lwe(&original_ct, &ksk, &from_lwe, &to_lwe, &radix);

            let new_decrypted = new_sk.decrypt(&new_ct, &to_lwe, bits);

            assert_eq!(new_decrypted, msg);
        }
    }
}
