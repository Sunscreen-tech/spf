use rand::{rng, RngCore};
use sunscreen_gpu_runtime::DeviceId;

use crate::{entities::{BootstrapKeyFft, DstArray, GlweCiphertext, LweCiphertext, Polynomial, UnivariateLookupTable}, gpu::{get_runtimes, ops::{bootstrapping::gpu_generalized_functional_bootstrap, keys::gpu_fft_bootstrap_key}, tests::PBS_RADIX_2_16}, high_level::{self, keygen}, ops::encryption::{decrypt_glwe_ciphertext, encrypt_lwe_ciphertext, trivially_encrypt_lwe_ciphertext}, PlaintextBits, RadixCount, RadixDecomposition, RadixLog, Torus, GLWE_1_2048_128, LWE_637_128};

#[test]
fn can_programmable_bootstrap() {
    let glwe = GLWE_1_2048_128;
    let lwe = LWE_637_128;
    let radix = PBS_RADIX_2_16;
    let bits = PlaintextBits(1);

    let num_blocks = 2;
    let runtimes = get_runtimes();
    let lwe_sk = keygen::generate_binary_lwe_sk(&lwe);
    let glwe_sk = keygen::generate_binary_glwe_sk(&glwe);
    let bsk = keygen::generate_bootstrapping_key(&lwe_sk, &glwe_sk, &lwe, &glwe, &radix);

    let mut bsk_fft = BootstrapKeyFft::new(&lwe, &glwe, &radix);

    for r in runtimes.iter() {
        let stream = r.make_stream(DeviceId(0)).unwrap();

        // FFT the bootstrapping key on the GPU.
        gpu_fft_bootstrap_key(&mut bsk_fft, &bsk, &lwe, &glwe, &radix, r, &stream).unwrap();

        stream.wait().unwrap();

        let mut outputs = DstArray::<GlweCiphertext<u64>>::new(num_blocks, glwe.dim);
        let mut inputs = DstArray::<LweCiphertext<u64>>::new(num_blocks, lwe.dim);

        for (i, ct) in inputs.iter_mut(lwe.dim).enumerate() {
            // Taken from the test in
            // `sunscreen_tfhe/src/ops/bootstrapping/programmable_bootstrapping.rs`,
            // out LUT maps the T_4 torus to the T_2 torus. So we, encrypt with 2 bits
            // and decrypt with 1 bit.
            let msg = Torus::encode(i as u64 % 2, PlaintextBits(2));

            // encrypt_lwe_ciphertext(ct, &lwe_sk, msg, &lwe);
            trivially_encrypt_lwe_ciphertext(ct, &msg, &lwe);

            dbg!(ct.a_b(&lwe).1);
        }
    
        // Fill the LUT with nonsense and we'll overwrite it with
        // the correct encoding.
        let lut = UnivariateLookupTable::<u64>::trivivial_multifunctional(
            [|x| x % 2, |x| (x + 1) % 2, |x| x % 2].as_slice(),
            &glwe,
            bits,
        );

        gpu_generalized_functional_bootstrap(
            &mut outputs,
            &inputs,
            &lut,
            &bsk_fft,
            0,
            3,
            &lwe.into(),
            &glwe.into(),
            &radix.into(),
            &r,
            &stream
        ).unwrap();

        stream.wait().unwrap();

        for (i, out) in outputs.iter(glwe.dim).enumerate() {
            let mut dbg_msg = Polynomial::zero(glwe.dim.polynomial_degree.0);
            decrypt_glwe_ciphertext(&mut dbg_msg, &out, &glwe_sk, &glwe);

            dbg!(i);
            for c in dbg_msg.coeffs().iter().take(8) {
                println!("pt {:0>64b}", c.inner());
            }

            let res = high_level::encryption::decrypt_glwe(&out, &glwe_sk, &glwe, bits);

            if i % 2 == 0 {
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
}