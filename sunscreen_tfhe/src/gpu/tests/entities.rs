use num::Complex;
use rand::{RngCore, rng};
use sunscreen_gpu_runtime::{DeviceId, launch_kernel};

use crate::{
    GLWE_1_2048_128, LWE_637_128, OverlaySize, PlaintextBits, Torus,
    dst::{AsMutSlice, AsSlice},
    entities::{
        BootstrapKeyFft, DstArray, GgswCiphertext, GgswCiphertextFft, GlevCiphertext,
        GlevCiphertextFft, GlweCiphertext, GlweCiphertextFft, GlweCiphertextRef, GlweSecretKey,
        Polynomial,
    },
    gpu::{
        get_runtimes, gpu_params,
        ops::keys::{gpu_fft_bootstrap_key, gpu_ifft_bootstrap_key},
        tests::{PBS_RADIX_2_16, get_shared_memory_bytes},
    },
    high_level::{self, encryption::trivial_glwe},
    ops::encryption::{
        decrypt_ggsw_ciphertext, decrypt_glev_ciphertext, decrypt_glwe_ciphertext,
        encrypt_glwe_ciphertext_secret, encrypt_secret_glev_ciphertext,
        trivially_encrypt_glwe_ciphertext,
    },
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
                (r, stream, get_shared_memory_bytes())
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

#[test]
fn can_fft_roundtrip_glwe() {
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        let glwe = GLWE_1_2048_128;

        let glwe_sk = high_level::keygen::generate_binary_glwe_sk(&glwe);

        let mut glwe_in = DstArray::<GlweCiphertext<u64>>::new(num_blocks, glwe.dim);
        let glwe_out = DstArray::<GlweCiphertext<u64>>::new(num_blocks, glwe.dim);
        let glwe_fft_out = DstArray::<GlweCiphertextFft<Complex<f64>>>::new(num_blocks, glwe.dim);

        for (i, glwe_in) in glwe_in.iter_mut(glwe.dim).enumerate() {
            let mut msg = Polynomial::zero(glwe.dim.polynomial_degree.0);
            msg.coeffs_mut()[0] = i as u64 % 2;

            let ct =
                high_level::encryption::encrypt_glwe(&mut msg, &glwe_sk, &glwe, PlaintextBits(1));

            glwe_in.as_mut_slice().clone_from_slice(ct.as_slice());
        }

        let stream = r.make_stream(DeviceId::default()).unwrap();

        let tpb = glwe.dim.polynomial_degree.threads_per_block();
        let threads = num_blocks as u32 * tpb;

        let glwe_gpu = gpu_params::GlweDef::from(&glwe);

        unsafe {
            launch_kernel!(
                ((threads, tpb))
                ("can_roundtrip_fft_glwe")
                (r, stream, 32 * 1024)
                glwe_out,
                glwe_fft_out,
                glwe_in,
                glwe_gpu
            )
        }
        .unwrap();

        stream.wait().unwrap();

        for (i, actual) in glwe_out.iter(glwe.dim).enumerate() {
            let mut msg = Polynomial::zero(glwe.dim.polynomial_degree.0);

            decrypt_glwe_ciphertext(&mut msg, actual, &glwe_sk, &glwe);

            assert_eq!(msg.coeffs()[0].decode(PlaintextBits(1)), i as u64 % 2);

            for c in msg.coeffs().iter().skip(1) {
                assert_eq!(c.decode(PlaintextBits(1)), 0);
            }
        }
    }
}

#[test]
fn can_fft_roundtrip_glev() {
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        let glwe = GLWE_1_2048_128;
        let radix = PBS_RADIX_2_16;

        let glwe_sk = high_level::keygen::generate_binary_glwe_sk(&glwe);

        let mut glev_in = DstArray::<GlevCiphertext<u64>>::new(num_blocks, (glwe.dim, radix.count));
        let glev_out = DstArray::<GlevCiphertext<u64>>::new(num_blocks, (glwe.dim, radix.count));
        let glev_fft_out =
            DstArray::<GlevCiphertextFft<Complex<f64>>>::new(num_blocks, (glwe.dim, radix.count));

        for (i, glev_in) in glev_in.iter_mut((glwe.dim, radix.count)).enumerate() {
            let mut msg = Polynomial::zero(glwe.dim.polynomial_degree.0);
            msg.coeffs_mut()[0] = Torus::from(i as u64 % 2);

            encrypt_secret_glev_ciphertext(glev_in, &msg, &glwe_sk, &glwe, &radix);
        }

        let stream = r.make_stream(DeviceId::default()).unwrap();

        let tpb = glwe.dim.polynomial_degree.threads_per_block();
        let threads = num_blocks as u32 * tpb;

        let glwe_gpu = gpu_params::GlweDef::from(&glwe);
        let radix_gpu = gpu_params::RadixDecomposition::from(&radix);

        unsafe {
            launch_kernel!(
                ((threads, tpb))
                ("can_roundtrip_fft_glev")
                (r, stream, 32 * 1024)
                glev_out,
                glev_fft_out,
                glev_in,
                glwe_gpu,
                radix_gpu
            )
        }
        .unwrap();

        stream.wait().unwrap();

        for (i, actual) in glev_out.iter((glwe.dim, radix.count)).enumerate() {
            let mut msg = Polynomial::zero(glwe.dim.polynomial_degree.0);

            decrypt_glev_ciphertext(&mut msg, actual, &glwe_sk, &glwe, &radix);

            assert_eq!(msg.coeffs()[0].inner(), i as u64 % 2);

            for c in msg.coeffs().iter().skip(1) {
                assert_eq!(c.inner(), 0);
            }
        }
    }
}

#[test]
fn can_fft_roundtrip_ggsw() {
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        let glwe = GLWE_1_2048_128;
        let radix = PBS_RADIX_2_16;

        let glwe_sk = high_level::keygen::generate_binary_glwe_sk(&glwe);

        let mut ggsw_in = DstArray::<GgswCiphertext<u64>>::new(num_blocks, (glwe.dim, radix.count));
        let ggsw_out = DstArray::<GgswCiphertext<u64>>::new(num_blocks, (glwe.dim, radix.count));
        let ggsw_fft_out =
            DstArray::<GgswCiphertextFft<Complex<f64>>>::new(num_blocks, (glwe.dim, radix.count));

        for (i, ggsw_in) in ggsw_in.iter_mut((glwe.dim, radix.count)).enumerate() {
            let ct = high_level::encryption::encrypt_ggsw(
                i as u64 % 2,
                &glwe_sk,
                &glwe,
                &radix,
                PlaintextBits(1),
            );

            ggsw_in.as_mut_slice().clone_from_slice(ct.as_slice());
        }

        let stream = r.make_stream(DeviceId::default()).unwrap();

        let tpb = glwe.dim.polynomial_degree.threads_per_block();
        let threads = num_blocks as u32 * tpb;

        let glwe_gpu = gpu_params::GlweDef::from(&glwe);
        let radix_gpu = gpu_params::RadixDecomposition::from(&radix);

        unsafe {
            launch_kernel!(
                ((threads, tpb))
                ("can_roundtrip_fft_ggsw")
                (r, stream, 32 * 1024)
                ggsw_out,
                ggsw_fft_out,
                ggsw_in,
                glwe_gpu,
                radix_gpu
            )
        }
        .unwrap();

        stream.wait().unwrap();

        for (i, actual) in ggsw_out.iter((glwe.dim, radix.count)).enumerate() {
            let mut msg = Polynomial::zero(glwe.dim.polynomial_degree.0);

            decrypt_ggsw_ciphertext(&mut msg, actual, &glwe_sk, &glwe, &radix);

            println!("{:0>64b}", msg.coeffs()[0].inner());

            assert_eq!(msg.coeffs()[0].inner(), i as u64 % 2);

            for c in msg.coeffs().iter().skip(1) {
                assert_eq!(c.inner(), 0);
            }
        }
    }
}

#[test]
fn can_fft_roundtrip_bsk() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        let lwe = LWE_637_128;
        let glwe = GLWE_1_2048_128;
        let radix = PBS_RADIX_2_16;

        let lwe_sk = high_level::keygen::generate_binary_lwe_sk(&lwe);
        let glwe_sk = high_level::keygen::generate_binary_glwe_sk(&glwe);
        let bsk =
            high_level::keygen::generate_bootstrapping_key(&lwe_sk, &glwe_sk, &lwe, &glwe, &radix);
        let mut bsk_clone = bsk.clone();
        let mut bsk_fft = BootstrapKeyFft::new(&lwe, &glwe, &radix);

        let stream = r.make_stream(DeviceId::default()).unwrap();

        gpu_fft_bootstrap_key(&mut bsk_fft, &bsk, &lwe, &glwe, &radix, &r, &stream).unwrap();
        gpu_ifft_bootstrap_key(&mut bsk_clone, &bsk_fft, &lwe, &glwe, &radix, &r, &stream).unwrap();

        stream.wait().unwrap();

        for (actual, s) in bsk_clone.rows(&glwe, &radix).zip(lwe_sk.s()) {
            let mut msg = Polynomial::zero(glwe.dim.polynomial_degree.0);

            decrypt_ggsw_ciphertext(&mut msg, actual, &glwe_sk, &glwe, &radix);

            assert_eq!(msg.coeffs()[0].inner(), *s);

            for c in msg.coeffs().iter().skip(1) {
                assert_eq!(c.inner(), 0);
            }
        }
    }
}

#[test]
fn can_recover_lwe_sk_from_bsk() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        let lwe = LWE_637_128;
        let glwe = GLWE_1_2048_128;
        let radix = PBS_RADIX_2_16;

        let lwe_sk = high_level::keygen::generate_binary_lwe_sk(&lwe);
        let glwe_sk = high_level::keygen::generate_binary_glwe_sk(&glwe);
        let bsk =
            high_level::keygen::generate_bootstrapping_key(&lwe_sk, &glwe_sk, &lwe, &glwe, &radix);
        let mut bsk_fft = BootstrapKeyFft::new(&lwe, &glwe, &radix);

        let mut glwe_in = DstArray::<GlweCiphertext<u64>>::new(lwe.dim.0, glwe.dim);
        let glwe_out = glwe_in.clone();

        for g in glwe_in.iter_mut(glwe.dim) {
            let mut msg = Polynomial::<Torus<u64>>::zero(glwe.dim.polynomial_degree.0);
            msg.coeffs_mut()[0] = Torus::encode(1, PlaintextBits(1));

            // encrypt_glwe_ciphertext_secret(g, &msg, &glwe_sk, &glwe);
            trivially_encrypt_glwe_ciphertext(g, &msg, &glwe);
        }

        let tpb = glwe.dim.polynomial_degree.threads_per_block();
        //let threads = tpb * lwe.dim.0 as u32;
        let threads = tpb;
        let stream = r.make_stream(DeviceId::default()).unwrap();

        gpu_fft_bootstrap_key(&mut bsk_fft, &bsk, &lwe, &glwe, &radix, &r, &stream).unwrap();

        stream.wait().unwrap();

        let lwe_gpu = gpu_params::LweDef::from(&lwe);
        let glwe_gpu: gpu_params::GlweDef = gpu_params::GlweDef::from(&glwe);
        let radix_gpu = gpu_params::RadixDecomposition::from(&radix);

        unsafe {
            launch_kernel!(
                ((threads, tpb))
                ("can_recover_lwe_sk_from_bsk")
                (r, stream, 96 * 1024)
                glwe_out,
                glwe_in,
                bsk_fft,
                lwe_gpu,
                glwe_gpu,
                radix_gpu
            )
        }
        .unwrap();

        stream.wait().unwrap();

        for (actual, expected) in glwe_out.iter(glwe.dim).zip(lwe_sk.s()) {
            let mut msg = Polynomial::zero(glwe.dim.polynomial_degree.0);
            decrypt_glwe_ciphertext(&mut msg, actual, &glwe_sk, &glwe);

            assert_eq!(msg.coeffs()[0].decode(PlaintextBits(1)), *expected);

            for c in msg.coeffs().iter().skip(1) {
                println!("{:0>64b}", c.inner());
                assert_eq!(c.decode(PlaintextBits(1)), 0);
            }
        }
    }
}
