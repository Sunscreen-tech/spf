use crate::{Error, Result};
use sunscreen_tfhe::{
    entities::{GgswCiphertextRef, GlweCiphertextRef, GlweSecretKeyRef, Polynomial, PolynomialRef},
    ops::encryption::{decrypt_glwe_ciphertext, scale_msg_by_gadget_factor},
    polynomial::polynomial_external_mad,
    GlweDef, PlaintextBits, RadixDecomposition, Torus,
};

/// Returns the noise of each coefficient
pub fn measure_noise_glwe(
    ct: &GlweCiphertextRef<u64>,
    sk: &GlweSecretKeyRef<u64>,
    expected: &PolynomialRef<Torus<u64>>,
    params: &GlweDef,
    plaintext_bits: PlaintextBits,
) -> Result<Vec<f64>> {
    let mut result = Polynomial::zero(params.dim.polynomial_degree.0);

    decrypt_glwe_ciphertext(&mut result, ct, sk, params);

    result
        .coeffs()
        .iter()
        .zip(expected.coeffs().iter())
        .map(|(a, e)| {
            if a.decode(plaintext_bits) != e.decode(plaintext_bits) {
                Err(Error::TooMuchNoise)
            } else {
                Ok(a.normalized_torus_distance(e))
            }
        })
        .collect::<Result<Vec<_>>>()
}

/// Measures the noise in the GGSW ciphertext requiring the largest plaintext space to represent.
pub fn measure_noise_ggsw(
    ct: &GgswCiphertextRef<u64>,
    sk: &GlweSecretKeyRef<u64>,
    expected: bool,
    params: &GlweDef,
    cbs_radix: &RadixDecomposition,
) -> Result<Vec<f64>> {
    // Our expected message is 1/B^{\ell} * m * s. Fill in the m polynomial.
    let mut msg_poly = Polynomial::zero(params.dim.polynomial_degree.0);
    msg_poly.coeffs_mut()[0] = expected as u64;

    let mut scaled = Polynomial::zero(params.dim.polynomial_degree.0);

    // Scale by 1/B^{\ell}
    scale_msg_by_gadget_factor(
        &mut scaled,
        msg_poly.as_torus(),
        cbs_radix.radix_log.0,
        cbs_radix.count.0 - 1,
    );

    // Multiply by sk.
    let mut expected_poly = Polynomial::zero(params.dim.polynomial_degree.0);

    polynomial_external_mad(&mut expected_poly, &scaled, sk.s(params).next().unwrap());

    let expected_poly = expected_poly.map(|x| x.wrapping_neg());

    let glwe_ct = ct
        .rows(params, cbs_radix)
        .next()
        .unwrap()
        .glwe_ciphertexts(params)
        .next_back()
        .unwrap();

    measure_noise_glwe(
        glwe_ct,
        sk,
        expected_poly.as_torus(),
        params,
        PlaintextBits((cbs_radix.radix_log.0 * cbs_radix.count.0) as u32),
    )
}
