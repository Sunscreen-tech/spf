use num::Complex;
use rand::{RngCore, thread_rng};
use sunscreen_gpu_runtime::launch_kernel;

use crate::{
    GLWE_1_2048_128, GlweDef, OverlaySize, PlaintextBits, Torus,
    dst::{AsSlice, FromSlice},
    entities::{
        GlweCiphertext, GlweCiphertextFftRef, GlweCiphertextRef, GlweSecretKey, Polynomial,
        PolynomialFftRef,
    },
    gpu::test_utils::{PolyDegreeInfo, SUPPORTED_POLY_DEGREES, get_runtimes},
    high_level,
    ops::{
        ciphertext::{add_glwe_ciphertexts, sub_glwe_ciphertexts},
        fft_ops::glwe_polynomial_mad,
    },
};

fn glwe_op_test<F>(baseline_op: F, kernel_name: &str)
where
    F: Fn(&mut GlweCiphertextRef<u64>, &GlweCiphertextRef<u64>, &GlweCiphertextRef<u64>, &GlweDef),
{
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let num_blocks = 13;

            let glwe = GLWE_1_2048_128;

            let sk = GlweSecretKey::generate_binary(&glwe);

            let a_ct = (0..num_blocks)
                .map(|_| {
                    let pt = Polynomial::new(
                        &(0..glwe.dim.polynomial_degree.0)
                            .map(|i| i as u64 % 2)
                            .collect::<Vec<_>>(),
                    );

                    sk.encode_encrypt_glwe(&pt, &glwe, PlaintextBits(1))
                })
                .collect::<Vec<_>>();

            let a_flat = a_ct
                .iter()
                .flat_map(|x| x.as_slice().to_owned())
                .collect::<Vec<_>>();

            let b_ct = (0..num_blocks)
                .map(|_| {
                    let pt = Polynomial::new(
                        &(0..glwe.dim.polynomial_degree.0)
                            .map(|i| i as u64 % 2)
                            .collect::<Vec<_>>(),
                    );

                    sk.encode_encrypt_glwe(&pt, &glwe, PlaintextBits(1))
                })
                .collect::<Vec<_>>();

            let b_flat = b_ct
                .iter()
                .flat_map(|x| x.as_slice().to_owned())
                .collect::<Vec<_>>();

            let c = r.allocate::<Torus<u64>>(a_flat.len()).unwrap();
            let mut a = r.allocate::<Torus<u64>>(a_flat.len()).unwrap();
            let mut b = r.allocate::<Torus<u64>>(b_flat.len()).unwrap();
            a.as_mut_slice().copy_from_slice(&a_flat);
            b.as_mut_slice().copy_from_slice(&b_flat);

            let stream = r.make_stream().unwrap();

            let tpb = d.threads_per_block();
            let t = num_blocks * tpb;

            unsafe {
                launch_kernel!(
                    ((t, tpb))
                    (kernel_name)
                    (r, stream, 0)
                    c,
                    a,
                    b
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for ((c, a), b) in c
                .as_slice()
                .chunks(GlweCiphertextRef::<u64>::size(glwe.dim))
                .zip(a_ct.iter())
                .zip(b_ct.iter())
            {
                let mut expected = GlweCiphertext::<u64>::new(&glwe);

                baseline_op(&mut expected, a, b, &glwe);

                assert_eq!(c, expected.as_slice())
            }
        }
    }
}

#[test]
fn can_glwe_sub() {
    glwe_op_test(
        |c, a, b, def| sub_glwe_ciphertexts(c, a, b, def),
        "can_glwe_sub",
    );
}

#[test]
fn can_glwe_add() {
    glwe_op_test(
        |c, a, b, def| add_glwe_ciphertexts(c, a, b, def),
        "can_glwe_add",
    );
}

#[test]
fn can_glwe_polynomial_mad() {
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        let glwe = GLWE_1_2048_128;

        let sk = GlweSecretKey::generate_binary(&glwe);

        let c_glwe = (0..num_blocks)
            .map(|_| {
                let msg = (0..glwe.dim.polynomial_degree.0)
                    .map(|_| thread_rng().next_u64() % 2)
                    .collect::<Vec<_>>();
                let msg = Polynomial::new(&msg);

                let ct = sk.encode_encrypt_glwe(&msg, &glwe, PlaintextBits(1));

                high_level::fft::fft_glwe(&ct, &glwe)
            })
            .collect::<Vec<_>>();

        let a_glwe = (0..num_blocks)
            .map(|_| {
                let msg = (0..glwe.dim.polynomial_degree.0)
                    .map(|_| thread_rng().next_u64() % 2)
                    .collect::<Vec<_>>();
                let msg = Polynomial::new(&msg);

                let ct = sk.encode_encrypt_glwe(&msg, &glwe, PlaintextBits(1));

                high_level::fft::fft_glwe(&ct, &glwe)
            })
            .collect::<Vec<_>>();

        let b_poly = (0..num_blocks)
            .map(|_| {
                let poly = (0..glwe.dim.polynomial_degree.0)
                    .map(|_| thread_rng().next_u64() % 16)
                    .collect::<Vec<_>>();
                let poly = Polynomial::new(&poly);

                high_level::fft::fft_polynomial(&poly, &glwe.dim.polynomial_degree)
            })
            .collect::<Vec<_>>();

        let mut c = r
            .allocate::<Complex<f64>>(
                num_blocks * GlweCiphertextFftRef::<Complex<f64>>::size(glwe.dim),
            )
            .unwrap();
        let mut a = r
            .allocate::<Complex<f64>>(
                num_blocks * GlweCiphertextFftRef::<Complex<f64>>::size(glwe.dim),
            )
            .unwrap();
        let mut b = r
            .allocate::<Complex<f64>>(
                num_blocks * PolynomialFftRef::<Complex<f64>>::size(glwe.dim.polynomial_degree),
            )
            .unwrap();

        c.as_mut_slice().clone_from_slice(
            c_glwe
                .iter()
                .flat_map(|x| x.as_slice().to_vec())
                .collect::<Vec<_>>()
                .as_slice(),
        );
        a.as_mut_slice().clone_from_slice(
            a_glwe
                .iter()
                .flat_map(|x| x.as_slice().to_vec())
                .collect::<Vec<_>>()
                .as_slice(),
        );
        b.as_mut_slice().clone_from_slice(
            b_poly
                .iter()
                .flat_map(|x| x.as_slice().to_vec())
                .collect::<Vec<_>>()
                .as_slice(),
        );

        let stream = r.make_stream().unwrap();

        let tpb = PolyDegreeInfo(glwe.dim.polynomial_degree.0 as u32).threads_per_block();
        let threads = num_blocks as u32 * tpb;

        unsafe {
            launch_kernel!(
                ((threads, tpb))
                ("can_glwe_polynomial_mad")
                (r, stream, 0)
                c,
                a,
                b
            )
        }
        .unwrap();

        stream.wait().unwrap();

        for i in 0..num_blocks {
            let mut expected_fft = c_glwe[i].clone();
            glwe_polynomial_mad(&mut expected_fft, &a_glwe[i], &b_poly[i], &glwe);
            let mut expected = GlweCiphertext::new(&glwe);
            expected_fft.ifft(&mut expected, &glwe);

            let expected = sk.decrypt_decode_glwe(&expected, &glwe, PlaintextBits(1));

            let actual_fft = c
                .as_slice()
                .chunks(GlweCiphertextFftRef::size(glwe.dim))
                .nth(i)
                .unwrap();

            let actual_fft = GlweCiphertextFftRef::from_slice(actual_fft);
            let mut actual = GlweCiphertext::new(&glwe);
            actual_fft.ifft(&mut actual, &glwe);
            let actual = sk.decrypt_decode_glwe(&actual, &glwe, PlaintextBits(1));

            assert_eq!(actual, expected);
        }
    }
}
