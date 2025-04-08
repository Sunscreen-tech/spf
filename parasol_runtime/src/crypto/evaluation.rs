use std::{borrow::BorrowMut, ops::Deref, sync::Arc};

use sunscreen_tfhe::{
    entities::{GgswCiphertext, GlweCiphertextFft},
    ops::{
        bootstrapping::{circuit_bootstrap, rotate_glwe_positive_monomial_negacyclic},
        ciphertext::sample_extract,
        fft_ops::{cmux, glev_cmux, glwe_ggsw_mad, scheme_switch_fft},
        keyswitch::lwe_keyswitch::keyswitch_lwe_to_lwe,
    },
};

use crate::params::Params;

use super::{
    encryption::{
        Encryption, L0LweCiphertext, L1GgswCiphertext, L1GlweCiphertext, L1LweCiphertext,
    },
    L1GlevCiphertext, ServerKeyFft, TrivialOne, TrivialZero,
};

#[derive(Clone)]
/// Performs FHE operations that don't require the server key.
pub struct KeylessEvaluation {
    pub params: Params,
    #[allow(unused)]
    l1glwe_zero: L1GlweCiphertext,
    l1glwe_one: L1GlweCiphertext,
}

impl KeylessEvaluation {
    pub fn new(params: &Params, enc: &Encryption) -> Self {
        let l1glwe_zero = L1GlweCiphertext::trivial_zero(enc);
        let l1glwe_one = L1GlweCiphertext::trivial_one(enc);

        Self {
            params: params.clone(),
            l1glwe_zero,
            l1glwe_one,
        }
    }

    /// Given a GLWE encryption of `m={0, 1}[X]^N`, compute the coefficient-wise binary not operation.
    pub fn not(&self, output: &mut L1GlweCiphertext, input: &L1GlweCiphertext) {
        output.0 = (input.0).as_ref() + self.l1glwe_one.0.as_ref();
    }

    /// Given a GLWE encryption of `m={0, 1}[X]^N`, compute the coefficient-wise binary xor operation.
    pub fn xor(&self, output: &mut L1GlweCiphertext, a: &L1GlweCiphertext, b: &L1GlweCiphertext) {
        output.0 = a.0.as_ref() + b.0.as_ref();
    }

    /// Multiplies the given `input` GLWE ciphertext by x^n.
    pub fn mul_xn(&self, output: &mut L1GlweCiphertext, input: &L1GlweCiphertext, n: usize) {
        rotate_glwe_positive_monomial_negacyclic(
            &mut output.0,
            &input.0,
            n,
            &self.params.l1_params,
        );
    }

    pub fn cmux(
        &self,
        output: &mut L1GlweCiphertext,
        sel: &L1GgswCiphertext,
        a: &L1GlweCiphertext,
        b: &L1GlweCiphertext,
    ) {
        cmux(
            &mut output.0,
            &a.0,
            &b.0,
            &sel.0,
            &self.params.l1_params,
            &self.params.cbs_radix,
        );
    }

    pub fn glev_cmux(
        &self,
        output: &mut L1GlevCiphertext,
        sel: &L1GgswCiphertext,
        a: &L1GlevCiphertext,
        b: &L1GlevCiphertext,
    ) {
        glev_cmux(
            &mut output.0,
            &a.0,
            &b.0,
            &sel.0,
            &self.params.l1_params,
            &self.params.cbs_radix,
        );
    }

    pub fn multiply_glwe_ggsw(
        &self,
        output: &mut L1GlweCiphertext,
        glwe: &L1GlweCiphertext,
        ggsw: &L1GgswCiphertext,
    ) {
        output.0.clear();

        let mut output_fft = GlweCiphertextFft::new(&self.params.l1_params);

        glwe_ggsw_mad(
            &mut output_fft,
            &glwe.0,
            &ggsw.0,
            &self.params.l1_params,
            &self.params.cbs_radix,
        );

        output_fft.ifft(&mut output.0, &self.params.l1_params);
    }

    pub fn sample_extract_l1(
        &self,
        output: &mut L1LweCiphertext,
        input: &L1GlweCiphertext,
        idx: usize,
    ) {
        sample_extract(&mut output.0, &input.0, idx, &self.params.l1_params);
    }
}

#[derive(Clone)]
/// Performs FHE operations, including those that require the server key.
///
/// # Remarks
/// This type exposes low-level operations and one should generally prefer the higher-level
/// [`crate::fluent`] API or using the Parasol processor.
///
/// All FHE operations in the evaluation run on the current thread.
pub struct Evaluation {
    keyless_eval: KeylessEvaluation,
    server_key: Arc<ServerKeyFft>,
    l1ggsw_zero: L1GgswCiphertext,
    l1ggsw_one: L1GgswCiphertext,
}

impl Deref for Evaluation {
    type Target = KeylessEvaluation;

    fn deref(&self) -> &Self::Target {
        &self.keyless_eval
    }
}

impl Evaluation {
    /// Create a new [`Evaluation`].
    pub fn new(server_key: Arc<ServerKeyFft>, params: &Params, enc: &Encryption) -> Self {
        let mk_ggsw = |msg: bool| {
            let lwe = if msg {
                enc.trivial_lwe_l0_one()
            } else {
                enc.trivial_lwe_l0_zero()
            };

            let mut tmp = GgswCiphertext::new(&params.l1_params, &params.cbs_radix);

            circuit_bootstrap(
                &mut tmp,
                &lwe.0,
                &server_key.cbs_key,
                &server_key.pfks_key,
                &params.l0_params,
                &params.l1_params,
                &params.l2_params,
                &params.pbs_radix,
                &params.cbs_radix,
                &params.pfks_radix,
            );

            let mut output = enc.allocate_ggsw_l1();

            tmp.fft(output.0.borrow_mut(), &params.l1_params, &params.cbs_radix);

            output
        };

        let l1ggsw_zero = mk_ggsw(false);
        let l1ggsw_one = mk_ggsw(true);

        Self {
            keyless_eval: KeylessEvaluation::new(params, enc),
            server_key,
            l1ggsw_zero,
            l1ggsw_one,
        }
    }

    /// Perform a circuit bootstrap operation, converting an [`L0LweCiphertext`] into an
    /// [`L1GgswCiphertext`].
    ///
    /// # See also
    /// [`circuit_bootstrap`]
    pub fn circuit_bootstrap(&self, output: &mut L1GgswCiphertext, input: &L0LweCiphertext) {
        let mut tmp = GgswCiphertext::new(&self.params.l1_params, &self.params.cbs_radix);

        circuit_bootstrap(
            &mut tmp,
            &input.0,
            &self.server_key.cbs_key,
            &self.server_key.pfks_key,
            &self.params.l0_params,
            &self.params.l1_params,
            &self.params.l2_params,
            &self.params.pbs_radix,
            &self.params.cbs_radix,
            &self.params.pfks_radix,
        );

        tmp.fft(
            output.0.borrow_mut(),
            &self.params.l1_params,
            &self.params.cbs_radix,
        );
    }

    /// Converts an [`L1GlevCiphertext`] to an [`L1GgswCiphertext`].
    ///
    /// # See also
    /// [`scheme_switch_fft`]
    pub fn scheme_switch(&self, output: &mut L1GgswCiphertext, input: &L1GlevCiphertext) {
        scheme_switch_fft(
            &mut output.0,
            &input.0,
            &self.server_key.ss_key,
            &self.params.l1_params,
            &self.params.cbs_radix,
            &self.params.ss_radix,
        );
    }

    /// Convert an [`L1LweCiphertext`] to an [`L0LweCiphertext`].
    ///
    /// # See also
    /// [`keyswitch_lwe_to_lwe`]
    pub fn keyswitch_lwe_l1_lwe_l0(&self, output: &mut L0LweCiphertext, input: &L1LweCiphertext) {
        keyswitch_lwe_to_lwe(
            &mut output.0,
            &input.0,
            &self.server_key.ks_key,
            &self.params.l1_params.as_lwe_def(),
            &self.params.l0_params,
            &self.params.ks_radix,
        );
    }

    /// Returns a precomputed GGSW encryption of zero
    pub fn l1ggsw_zero(&self) -> &L1GgswCiphertext {
        &self.l1ggsw_zero
    }

    /// Returns a precomputed GGSW encryption of one
    pub fn l1ggsw_one(&self) -> &L1GgswCiphertext {
        &self.l1ggsw_one
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, RngCore};
    use sunscreen_tfhe::entities::Polynomial;

    use crate::{
        crypto::encryption::Encryption,
        params::DEFAULT_80,
        test_utils::{get_secret_keys_80, get_server_keys_80},
    };

    use super::*;

    #[test]
    fn can_circuit_bootstrap() {
        let secret = get_secret_keys_80();
        let server = get_server_keys_80();

        let enc = Encryption::new(&DEFAULT_80);
        let eval = Evaluation::new(server, &DEFAULT_80, &enc);

        let mut ggsw = enc.allocate_ggsw_l1();

        let lwe = enc.encrypt_lwe_l0_secret(false, &secret);
        eval.circuit_bootstrap(&mut ggsw, &lwe);
        assert!(!enc.decrypt_ggsw_l1(&ggsw, &secret));

        let lwe = enc.encrypt_lwe_l0_secret(true, &secret);
        eval.circuit_bootstrap(&mut ggsw, &lwe);
        assert!(enc.decrypt_ggsw_l1(&ggsw, &secret));
    }

    #[test]
    fn can_lwe_keyswitch() {
        let secret = get_secret_keys_80();
        let server = get_server_keys_80();

        let enc = Encryption::new(&DEFAULT_80);
        let eval = Evaluation::new(server, &DEFAULT_80, &enc);

        let mut lwe_0 = enc.allocate_lwe_l0();

        let lwe_1 = enc.encrypt_lwe_l1_secret(false, &secret);
        eval.keyswitch_lwe_l1_lwe_l0(&mut lwe_0, &lwe_1);

        assert!(!enc.decrypt_lwe_l0(&lwe_0, &secret));

        let lwe_1 = enc.encrypt_lwe_l1_secret(true, &secret);
        eval.keyswitch_lwe_l1_lwe_l0(&mut lwe_0, &lwe_1);

        assert!(enc.decrypt_lwe_l0(&lwe_0, &secret));
    }

    #[test]
    fn can_cmux() {
        let secret = get_secret_keys_80();
        let server = get_server_keys_80();

        let enc = Encryption::new(&DEFAULT_80);
        let eval = Evaluation::new(server, &DEFAULT_80, &enc);

        let mut ggsw = enc.allocate_ggsw_l1();
        let mut result = enc.allocate_glwe_l1();

        let zero = enc.trivial_glwe_l1_zero();
        let one = enc.trivial_glwe_l1_one();

        let sel = enc.encrypt_lwe_l0_secret(false, &secret);
        eval.circuit_bootstrap(&mut ggsw, &sel);
        eval.cmux(&mut result, &ggsw, &zero, &one);
        assert_eq!(enc.decrypt_glwe_l1(&result, &secret).coeffs()[0], 0);

        let sel = enc.encrypt_lwe_l0_secret(true, &secret);
        eval.circuit_bootstrap(&mut ggsw, &sel);
        eval.cmux(&mut result, &ggsw, &zero, &one);
        assert_eq!(enc.decrypt_glwe_l1(&result, &secret).coeffs()[0], 1);
    }

    #[test]
    fn can_sample_extract() {
        let secret = get_secret_keys_80();
        let server = get_server_keys_80();

        let enc = Encryption::new(&DEFAULT_80);
        let eval = Evaluation::new(server, &DEFAULT_80, &enc);

        let mut poly = vec![0; DEFAULT_80.l1_poly_degree().0];
        poly[1] = 1;
        let poly = Polynomial::new(&poly);

        let ct = enc.encrypt_glwe_l1_secret(&poly, &secret);
        let mut lwe = enc.allocate_lwe_l1();
        eval.sample_extract_l1(&mut lwe, &ct, 1);

        assert!(enc.decrypt_lwe_l1(&lwe, &secret));
    }

    #[test]
    fn can_not() {
        let secret = get_secret_keys_80();
        let server = get_server_keys_80();

        let enc = Encryption::new(&DEFAULT_80);
        let eval = Evaluation::new(server, &DEFAULT_80, &enc);

        let mut output = enc.allocate_glwe_l1();

        // Test negating one
        let poly = vec![0; DEFAULT_80.l1_poly_degree().0];
        let poly = Polynomial::new(&poly);
        let input = enc.encrypt_glwe_l1_secret(&poly, &secret);

        eval.not(&mut output, &input);

        assert_eq!(enc.decrypt_glwe_l1(&output, &secret).coeffs()[0], 1);

        // Test negating zero
        let mut poly = vec![0; DEFAULT_80.l1_poly_degree().0];
        poly[0] = 1;
        let poly = Polynomial::new(&poly);

        let input = enc.encrypt_glwe_l1_secret(&poly, &secret);

        eval.not(&mut output, &input);

        assert_eq!(enc.decrypt_glwe_l1(&output, &secret).coeffs()[0], 0);
    }

    #[test]
    fn can_xor() {
        let secret = get_secret_keys_80();
        let server = get_server_keys_80();

        let enc = Encryption::new(&DEFAULT_80);
        let eval = Evaluation::new(server, &DEFAULT_80, &enc);

        let mut output = enc.allocate_glwe_l1();

        let zero_poly = vec![0; DEFAULT_80.l1_poly_degree().0];
        let zero_poly = Polynomial::new(&zero_poly);

        let mut one_poly = vec![0; DEFAULT_80.l1_poly_degree().0];
        one_poly[0] = 1;
        let one_poly = Polynomial::new(&one_poly);

        // Test 0 xor 0 = 0
        let a = enc.encrypt_glwe_l1_secret(&zero_poly, &secret);
        let b = enc.encrypt_glwe_l1_secret(&zero_poly, &secret);

        eval.xor(&mut output, &a, &b);

        assert_eq!(enc.decrypt_glwe_l1(&output, &secret).coeffs()[0], 0);

        // Test 0 xor 1 = 1
        let a = enc.encrypt_glwe_l1_secret(&zero_poly, &secret);
        let b = enc.encrypt_glwe_l1_secret(&one_poly, &secret);

        eval.xor(&mut output, &a, &b);

        assert_eq!(enc.decrypt_glwe_l1(&output, &secret).coeffs()[0], 1);

        // Test 1 xor 0 = 1
        let a = enc.encrypt_glwe_l1_secret(&one_poly, &secret);
        let b = enc.encrypt_glwe_l1_secret(&zero_poly, &secret);

        eval.xor(&mut output, &a, &b);

        assert_eq!(enc.decrypt_glwe_l1(&output, &secret).coeffs()[0], 1);

        // Test 1 xor 1 = 0
        let a = enc.encrypt_glwe_l1_secret(&one_poly, &secret);
        let b = enc.encrypt_glwe_l1_secret(&one_poly, &secret);

        eval.xor(&mut output, &a, &b);

        assert_eq!(enc.decrypt_glwe_l1(&output, &secret).coeffs()[0], 0);
    }

    #[test]
    fn can_multiply_glwe_ggsw() {
        let secret = get_secret_keys_80();
        let server = get_server_keys_80();

        let enc = Encryption::new(&DEFAULT_80);
        let eval = Evaluation::new(server, &DEFAULT_80, &enc);

        for a in [false, true] {
            for b in [false, true] {
                let mut poly = Polynomial::new(&vec![0u64; enc.params.l1_poly_degree().0]);
                poly.coeffs_mut()[0] = a as u64;

                let a_enc = enc.encrypt_glwe_l1_secret(&poly, &secret);
                let b_enc = enc.encrypt_ggsw_l1_secret(b, &secret);
                let mut output = enc.allocate_glwe_l1();

                eval.multiply_glwe_ggsw(&mut output, &a_enc, &b_enc);

                let actual = enc.decrypt_glwe_l1(&output, &secret);

                assert_eq!(actual.coeffs()[0], (a && b) as u64);

                for i in 1..eval.params.l1_poly_degree().0 {
                    assert_eq!(actual.coeffs()[i], 0);
                }
            }
        }
    }

    #[test]
    fn can_mul_xn() {
        let sk = get_secret_keys_80();
        let server = get_server_keys_80();

        let enc = Encryption::new(&DEFAULT_80);
        let eval = Evaluation::new(server, &DEFAULT_80, &enc);

        let mut msg = Polynomial::<u64>::zero(DEFAULT_80.l1_params.dim.polynomial_degree.0);

        msg.coeffs_mut()[0] = 1;
        msg.coeffs_mut()[2] = 1;

        let ct = enc.encrypt_glwe_l1_secret(&msg, &sk);
        let mut output = enc.allocate_glwe_l1();

        eval.mul_xn(&mut output, &ct, 5);

        let ans = enc.decrypt_glwe_l1(&output, &sk);

        for i in 0..DEFAULT_80.l1_poly_degree().0 {
            let expected = if i == 5 || i == 7 { 1 } else { 0 };

            assert_eq!(ans.coeffs()[i], expected);
        }
    }

    #[test]
    fn can_scheme_switch() {
        let sk = get_secret_keys_80();
        let server = get_server_keys_80();

        let enc = Encryption::new(&DEFAULT_80);
        let eval = Evaluation::new(server, &DEFAULT_80, &enc);

        let mut msg = Polynomial::zero(DEFAULT_80.l1_poly_degree().0);
        msg.coeffs_mut()[0] = 1;

        let glev = enc.encrypt_glev_l1_secret(&msg, &sk);

        let mut ggsw = enc.allocate_ggsw_l1();
        eval.scheme_switch(&mut ggsw, &glev);

        assert_eq!(enc.decrypt_ggsw_l1(&ggsw, &sk), msg.coeffs()[0] == 1);
    }

    #[test]
    fn can_otp_transcipher() {
        let enc = Encryption::new(&DEFAULT_80);
        let eval = KeylessEvaluation::new(&DEFAULT_80, &enc);
        let sk = get_secret_keys_80();

        let msg = Polynomial::new(
            &(0..DEFAULT_80.l1_poly_degree().0)
                .map(|_| thread_rng().next_u64() % 2)
                .collect::<Vec<_>>(),
        );

        let ct = enc.encrypt_glwe_l1_secret(&msg, &sk);

        let otp = Polynomial::new(
            &(0..DEFAULT_80.l1_poly_degree().0)
                .map(|_| thread_rng().next_u64() % 2)
                .collect::<Vec<_>>(),
        );

        let otp_ct = enc.encrypt_glwe_l1_secret(&otp, &sk);

        let mut transcipher_ct = enc.allocate_glwe_l1();

        eval.xor(&mut transcipher_ct, &ct, &otp_ct);

        let transcipher_pt = enc.decrypt_glwe_l1(&transcipher_ct, &sk);

        let actual = transcipher_pt
            .coeffs()
            .iter()
            .zip(otp.coeffs().iter())
            .map(|(p, o)| (p ^ o) & 0x1)
            .collect::<Vec<_>>();
        let actual = Polynomial::new(&actual);

        assert_eq!(actual, msg);
    }
}
