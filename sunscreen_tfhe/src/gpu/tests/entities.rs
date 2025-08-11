use num::Complex;
use rand::{RngCore, rng};
use sunscreen_gpu_runtime::launch_kernel;

use crate::{
    GLWE_1_2048_128, OverlaySize, PlaintextBits, Torus,
    dst::{AsSlice, FromSlice},
    entities::{
        GlweCiphertext, GlweCiphertextFft, GlweCiphertextFftRef, GlweCiphertextRef, GlweSecretKey,
        Polynomial,
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

        let msg_cts = (0..num_blocks)
            .map(|x| {
                let msg = (0..glwe.dim.polynomial_degree.0)
                    .map(|_| rng().next_u64() % 2)
                    .collect::<Vec<_>>();
                let msg = Polynomial::new(&msg);
                let ct = sk.encode_encrypt_glwe(&msg, &glwe, PlaintextBits(1));

                (msg, ct)
            })
            .collect::<Vec<_>>();

        let msgs = msg_cts.iter().map(|x| x.0.clone()).collect::<Vec<_>>();
        let cts = msg_cts.iter().map(|x| x.1.clone()).collect::<Vec<_>>();

        let glwe_len = GlweCiphertextRef::<u64>::size(glwe.dim);
        let glwe_fft_len = GlweCiphertextFftRef::<Complex<f64>>::size(glwe.dim);

        //let mut x = r.allocate::<Torus<u64>>(num_blocks * glwe_len).unwrap();
        //let y = r.allocate::<Torus<u64>>(num_blocks * glwe_len).unwrap();
        //let y_fft = r
        //     .allocate::<Complex<f64>>(num_blocks * glwe_fft_len)
        //     .unwrap();

        // x.as_mut_slice().copy_from_slice(
        //     &cts.iter()
        //         .flat_map(|x| x.as_slice())
        //         .copied()
        //         .collect::<Vec<_>>(),
        // );

        let stream = r.make_stream(0.into()).unwrap();

        let tpb = glwe.dim.polynomial_degree.threads_per_block();
        let threads = num_blocks as u32 * tpb;

        unsafe {
            launch_kernel!(
                ((threads, tpb))
                ("compare_glwe_fft")
                (r, stream)
                y,
                y_fft,
                x
            )
        }
        .unwrap();

        stream.wait().unwrap();

        let mut mean_err = [0.0; 3];

        for i in 0..num_blocks {
            let mut fft = GlweCiphertextFft::new(&glwe);

            cts[i].fft(&mut fft, &glwe);

            let mut cpu_ifft = GlweCiphertext::<u64>::new(&glwe);
            fft.ifft(&mut cpu_ifft, &glwe);

            let mut cpu_roundtrip_msg =
                Polynomial::<Torus<u64>>::zero(glwe.dim.polynomial_degree.0);
            let mut gpu_roundtrip_msg = cpu_roundtrip_msg.clone();
            let mut no_fft_msg = cpu_roundtrip_msg.clone();

            decrypt_glwe_ciphertext(&mut cpu_roundtrip_msg, &cpu_ifft, &sk, &glwe);

            let gpu_roundtrip_ct =
                GlweCiphertextRef::from_slice(y.as_slice().chunks(glwe_len).nth(i).unwrap());
            decrypt_glwe_ciphertext(&mut gpu_roundtrip_msg, &gpu_roundtrip_ct, &sk, &glwe);

            decrypt_glwe_ciphertext(&mut no_fft_msg, &cts[i], &sk, &glwe);

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
