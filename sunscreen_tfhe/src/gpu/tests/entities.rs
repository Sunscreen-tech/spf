use num::Complex;
use rand::{RngCore, rng};
use sunscreen_gpu_runtime::launch_kernel;

use crate::{
    GLWE_1_2048_128, OverlaySize, PlaintextBits, Torus,
    dst::{AsMutSlice, AsSlice},
    entities::{
        DstArray, GlweCiphertext, GlweCiphertextFft, GlweCiphertextRef, GlweSecretKey, Polynomial,
    },
    gpu::get_runtimes,
    ops::encryption::decrypt_glwe_ciphertext,
};

#[test]
fn check_glwe_fft_noise() {
    let runtimes = get_runtimes();
    let num_blocks = 25;

    let glwe = GLWE_1_2048_128;

    for r in runtimes.iter() {
        let sk = GlweSecretKey::generate_binary(&glwe);

        let msgs = (0..num_blocks)
            .map(|_| {
                let msg = (0..glwe.dim.polynomial_degree.0)
                    .map(|_| rng().next_u64() % 2)
                    .collect::<Vec<_>>();
                Polynomial::new(&msg)
            })
            .collect::<Vec<_>>();

        let mut cts = DstArray::<GlweCiphertext<u64>>::new(num_blocks, glwe.dim);
        let results = cts.clone();
        let results_fft = DstArray::<GlweCiphertextFft<Complex<f64>>>::new(num_blocks, glwe.dim);

        for (ct, msg) in cts.iter_mut(glwe.dim).zip(msgs.iter()) {
            let ct_enc = sk.encode_encrypt_glwe(&msg, &glwe, PlaintextBits(1));

            ct.as_mut_slice().clone_from_slice(ct_enc.as_slice());
        }

        let glwe_len = GlweCiphertextRef::<u64>::size(glwe.dim);

        let stream = r.make_stream(0.into()).unwrap();

        let tpb = glwe.dim.polynomial_degree.threads_per_block();
        let threads = num_blocks as u32 * tpb;

        unsafe {
            launch_kernel!(
                ((threads, tpb))
                ("compare_glwe_fft")
                (r, stream)
                results,
                results_fft,
                cts
            )
        }
        .unwrap();

        stream.wait().unwrap();

        let mut mean_err = [0.0; 3];

        for i in 0..num_blocks {
            let mut fft = GlweCiphertextFft::new(&glwe);

            let result_ct = results.iter(glwe.dim).nth(i).unwrap();
            let input_ct = cts.iter(glwe.dim).nth(i).unwrap();
            input_ct.fft(&mut fft, &glwe);

            let mut cpu_ifft = GlweCiphertext::<u64>::new(&glwe);
            fft.ifft(&mut cpu_ifft, &glwe);

            let mut cpu_roundtrip_msg =
                Polynomial::<Torus<u64>>::zero(glwe.dim.polynomial_degree.0);
            let mut gpu_roundtrip_msg = cpu_roundtrip_msg.clone();
            let mut no_fft_msg = cpu_roundtrip_msg.clone();

            decrypt_glwe_ciphertext(&mut cpu_roundtrip_msg, &cpu_ifft, &sk, &glwe);

            decrypt_glwe_ciphertext(&mut gpu_roundtrip_msg, &result_ct, &sk, &glwe);

            decrypt_glwe_ciphertext(&mut no_fft_msg, input_ct, &sk, &glwe);

            for j in 0..glwe.dim.polynomial_degree.0 {
                assert_eq!(
                    no_fft_msg.coeffs()[j].decode(PlaintextBits(1)),
                    msgs[i].coeffs()[j]
                );
                assert_eq!(
                    cpu_roundtrip_msg.coeffs()[j].decode(PlaintextBits(1)),
                    msgs[i].coeffs()[j]
                );
                assert_eq!(
                    gpu_roundtrip_msg.coeffs()[j].decode(PlaintextBits(1)),
                    msgs[i].coeffs()[j]
                );

                let expected = Torus::encode(msgs[i].coeffs()[j], PlaintextBits(1));

                mean_err[0] += no_fft_msg.coeffs()[j].normalized_torus_distance(&expected);
                mean_err[1] += cpu_roundtrip_msg.coeffs()[j].normalized_torus_distance(&expected);
                mean_err[2] += gpu_roundtrip_msg.coeffs()[j].normalized_torus_distance(&expected);
            }
        }

        let samples = (num_blocks * glwe.dim.polynomial_degree.0) as f64;
        assert!(mean_err[0] / samples < 1e-15);
        assert!(mean_err[1] / samples < 1e-15);
        assert!(mean_err[2] / samples < 1e-15);
    }
}
