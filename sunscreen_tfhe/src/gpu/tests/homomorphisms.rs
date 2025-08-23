use sunscreen_gpu_runtime::launch_kernel;

use crate::{
    GLWE_1_2048_128, GlweDef, PlaintextBits,
    dst::AsSlice,
    entities::{DstArray, GlweCiphertext, GlweCiphertextRef, GlweSecretKey, Polynomial},
    gpu::{
        Scratch, get_runtimes,
        test_utils::SUPPORTED_POLY_DEGREES,
        tests::test_utils::{glwe_encrypt, random_msg, random_poly_mod},
    },
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

            let mut a_ct = DstArray::<GlweCiphertext<u64>>::new(num_blocks, glwe.dim);
            let mut b_ct = a_ct.clone();
            let c = a_ct.clone();

            glwe_encrypt(&mut a_ct, random_msg, &sk, &glwe);
            glwe_encrypt(&mut b_ct, random_msg, &sk, &glwe);

            let stream = r.make_stream(0.into()).unwrap();

            let tpb = d.threads_per_block();
            let t = num_blocks as u32 * tpb;

            unsafe {
                launch_kernel!(
                    ((t, tpb))
                    (kernel_name)
                    (r, stream)
                    c,
                    a_ct,
                    b_ct
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for i in 0..num_blocks {
                let a = a_ct.iter(glwe.dim).nth(i).unwrap();
                let b = b_ct.iter(glwe.dim).nth(i).unwrap();

                let mut expected = GlweCiphertext::new(&glwe);

                baseline_op(&mut expected, a, b, &glwe);

                // Check expected and actual are exactly the same ciphertext.
                let actual = c.iter(glwe.dim).nth(i).unwrap();

                assert_eq!(actual.as_slice(), expected.as_slice());
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

        let mut c_glwe = DstArray::<GlweCiphertext<u64>>::new(num_blocks, glwe.dim);
        let mut a_glwe = c_glwe.clone();

        glwe_encrypt(&mut c_glwe, random_msg, &sk, &glwe);
        glwe_encrypt(&mut a_glwe, random_msg, &sk, &glwe);

        let c_orig = c_glwe.clone();

        let mut b_poly = DstArray::<Polynomial<u64>>::new(num_blocks, glwe.dim.polynomial_degree);

        random_poly_mod(&mut b_poly, &glwe.dim.polynomial_degree, 0x1 << 16);
        //one_poly(&mut b_poly, &glwe.dim.polynomial_degree);

        let stream = r.make_stream(0.into()).unwrap();

        let tpb = glwe.dim.polynomial_degree.threads_per_block();
        let threads = num_blocks as u32 * tpb;

        let grid = (threads, tpb);
        let scratch = Scratch::new(r, grid).unwrap();

        unsafe {
            launch_kernel!(
                (grid)
                ("can_glwe_polynomial_mad")
                (r, stream)
                c_glwe,
                a_glwe,
                b_poly,
                scratch
            )
        }
        .unwrap();

        stream.wait().unwrap();

        for i in 0..num_blocks {
            let c_orig = c_orig.iter(glwe.dim).nth(i).unwrap();
            let a_glwe = a_glwe.iter(glwe.dim).nth(i).unwrap();
            let b_poly = b_poly.iter(glwe.dim.polynomial_degree).nth(i).unwrap();

            // Compute the actual message
            let actual = c_glwe.iter(glwe.dim).nth(i).unwrap();
            let actual_msg =
                high_level::encryption::decrypt_glwe(actual, &sk, &glwe, PlaintextBits(1));

            // Compute the expected message
            let a_glwe_fft = high_level::fft::fft_glwe(a_glwe, &glwe);
            let mut expected_fft = high_level::fft::fft_glwe(c_orig, &glwe);
            let b_poly_fft = high_level::fft::fft_polynomial(b_poly, &glwe.dim.polynomial_degree);

            glwe_polynomial_mad(&mut expected_fft, &a_glwe_fft, &b_poly_fft, &glwe);

            let mut expected = GlweCiphertext::<u64>::new(&glwe);
            expected_fft.ifft(&mut expected, &glwe);

            let expected_msg =
                high_level::encryption::decrypt_glwe(&expected, &sk, &glwe, PlaintextBits(1));

            assert_eq!(expected_msg.coeffs(), actual_msg.coeffs());
        }
    }
}

// #[test]
// fn can_polynomial_glev_mad() {
//     let runtimes = get_runtimes();
//     let num_blocks = 13;

//     for r in runtimes.iter() {
//         let radix = RadixDecomposition {
//             count: RadixCount(2),
//             radix_log: RadixLog(16),
//         };

//         let glwe = GLWE_1_2048_128;
//         let sk = GlweSecretKey::generate_binary(&glwe);

//         let c_glwe = (0..num_blocks)
//             .map(|_| {
//                 let msg = (0..glwe.dim.polynomial_degree.0)
//                     .map(|_| rng().next_u64() % 2)
//                     .collect::<Vec<_>>();
//                 let msg = Polynomial::new(&msg);

//                 let ct = sk.encode_encrypt_glwe(&msg, &glwe, PlaintextBits(1));

//                 high_level::fft::fft_glwe(&ct, &glwe)
//             })
//             .collect::<Vec<_>>();

//         let a_poly = (0..num_blocks)
//             .map(|_| {
//                 let poly = (0..glwe.dim.polynomial_degree.0)
//                     .map(|_| Torus::from(rng().next_u64()))
//                     .collect::<Vec<_>>();
//                 Polynomial::new(&poly)
//             })
//             .collect::<Vec<_>>();

//         let b_glev = (0..num_blocks)
//             .map(|_| {
//                 let msg = (0..glwe.dim.polynomial_degree.0)
//                     .map(|_| Torus::encode(rng().next_u64() % 2, PlaintextBits(1)))
//                     .collect::<Vec<_>>();
//                 let msg = Polynomial::new(&msg);

//                 let mut ct = GlevCiphertext::<u64>::new(&glwe, &radix);

//                 encrypt_secret_glev_ciphertext(&mut ct, &msg, &sk, &glwe, &radix);

//                 high_level::fft::fft_glev(&ct, &glwe, &radix)
//             })
//             .collect::<Vec<_>>();

//         let mut c = r
//             .allocate::<Complex<f64>>(
//                 num_blocks * GlweCiphertextFftRef::<Complex<f64>>::size(glwe.dim),
//             )
//             .unwrap();
//         let mut a = r
//             .allocate::<Torus<u64>>(
//                 num_blocks * PolynomialRef::<Torus<u64>>::size(glwe.dim.polynomial_degree),
//             )
//             .unwrap();
//         let mut b = r
//             .allocate::<Complex<f64>>(
//                 num_blocks * GlevCiphertextFftRef::<Complex<f64>>::size((glwe.dim, radix.count)),
//             )
//             .unwrap();

//         c.as_mut_slice().clone_from_slice(
//             c_glwe
//                 .iter()
//                 .flat_map(|x| x.as_slice().to_vec())
//                 .collect::<Vec<_>>()
//                 .as_slice(),
//         );
//         a.as_mut_slice().clone_from_slice(
//             a_poly
//                 .iter()
//                 .flat_map(|x| x.as_slice().to_vec())
//                 .collect::<Vec<_>>()
//                 .as_slice(),
//         );
//         b.as_mut_slice().clone_from_slice(
//             b_glev
//                 .iter()
//                 .flat_map(|x| x.as_slice().to_vec())
//                 .collect::<Vec<_>>()
//                 .as_slice(),
//         );

//         let stream = r.make_stream(0.into()).unwrap();

//         let tpb = glwe.dim.polynomial_degree.threads_per_block();
//         let threads = tpb * num_blocks as u32;

//         let grid = (threads, tpb);
//         let scratch = Scratch::new(r, grid).unwrap();

//         unsafe {
//             launch_kernel!(
//                 (grid)
//                 ("can_polynomial_glev_mad")
//                 (r, stream)
//                 c,
//                 a,
//                 b,
//                 scratch
//             )
//         }
//         .unwrap();

//         stream.wait().unwrap();

//         for i in 0..num_blocks {
//             let mut expected_fft = c_glwe[i].clone();
//             let mut scratch = Polynomial::zero(glwe.dim.polynomial_degree.0);
//             let decomp = PolynomialRadixIterator::new(&a_poly[i], &mut scratch, &radix);

//             decomposed_polynomial_glev_mad(&mut expected_fft, decomp, &b_glev[i], &glwe);
//             let mut expected = GlweCiphertext::new(&glwe);
//             expected_fft.ifft(&mut expected, &glwe);

//             let expected = sk.decrypt_decode_glwe(&expected, &glwe, PlaintextBits(1));

//             dbg!("actual");

//             let actual_fft = c
//                 .as_slice()
//                 .chunks(GlweCiphertextFftRef::size(glwe.dim))
//                 .nth(i)
//                 .unwrap();

//             let actual_fft = GlweCiphertextFftRef::from_slice(actual_fft);

//             let mut actual = GlweCiphertext::new(&glwe);
//             actual_fft.ifft(&mut actual, &glwe);

//             let actual = sk.decrypt_decode_glwe(&actual, &glwe, PlaintextBits(1));

//             assert_eq!(actual, expected);
//         }
//     }
// }

// #[test]
// fn can_glwe_ggsw_mad() {
//     let runtimes = get_runtimes();
//     let num_blocks = 13;

//     let radix = RadixDecomposition {
//         count: RadixCount(2),
//         radix_log: RadixLog(16),
//     };

//     let glwe = GLWE_1_2048_128;

//     for r in runtimes.iter() {
//         let sk = GlweSecretKey::generate_binary(&glwe);

//         let c_msg = (0..num_blocks)
//             .map(|_| rng().next_u64() % 2)
//             .collect::<Vec<_>>();
//         let c_glwe_fft = c_msg
//             .iter()
//             .map(|x| {
//                 let mut msg = Polynomial::zero(glwe.dim.polynomial_degree.0);
//                 msg.coeffs_mut()[0] = *x;

//                 let ct = sk.encode_encrypt_glwe(&msg, &glwe, PlaintextBits(1));
//                 high_level::fft::fft_glwe(&ct, &glwe)
//             })
//             .collect::<Vec<_>>();

//         let a_msg = (0..num_blocks)
//             .map(|_| rng().next_u64() % 2)
//             .collect::<Vec<_>>();
//         let a_glwe = a_msg
//             .iter()
//             .map(|x| {
//                 let mut msg = Polynomial::zero(glwe.dim.polynomial_degree.0);
//                 msg.coeffs_mut()[0] = *x;

//                 sk.encode_encrypt_glwe(&msg, &glwe, PlaintextBits(1))
//             })
//             .collect::<Vec<_>>();

//         let b_msg = (0..num_blocks)
//             .map(|_| rng().next_u64() % 2)
//             .collect::<Vec<_>>();

//         let b_ggsw_fft = b_msg
//             .iter()
//             .map(|x| {
//                 let mut msg = Polynomial::zero(glwe.dim.polynomial_degree.0);
//                 msg.coeffs_mut()[0] = *x;

//                 let ct = sk.encode_encrypt_ggsw(&msg, &glwe, &radix, PlaintextBits(1));
//                 high_level::fft::fft_ggsw(&ct, &glwe, &radix)
//             })
//             .collect::<Vec<_>>();

//         let mut c = r
//             .allocate::<Complex<f64>>(
//                 num_blocks * GlweCiphertextFftRef::<Complex<f64>>::size(glwe.dim),
//             )
//             .unwrap();
//         let mut a = r
//             .allocate::<Torus<u64>>(num_blocks * GlweCiphertextRef::<u64>::size(glwe.dim))
//             .unwrap();
//         let mut b = r
//             .allocate::<Complex<f64>>(
//                 num_blocks * GgswCiphertextFftRef::<Complex<f64>>::size((glwe.dim, radix.count)),
//             )
//             .unwrap();

//         c.as_mut_slice().clone_from_slice(
//             c_glwe_fft
//                 .iter()
//                 .flat_map(|x| x.as_slice().to_vec())
//                 .collect::<Vec<_>>()
//                 .as_slice(),
//         );
//         a.as_mut_slice().clone_from_slice(
//             a_glwe
//                 .iter()
//                 .flat_map(|x| x.as_slice().to_vec())
//                 .collect::<Vec<_>>()
//                 .as_slice(),
//         );
//         b.as_mut_slice().clone_from_slice(
//             b_ggsw_fft
//                 .iter()
//                 .flat_map(|x| x.as_slice().to_vec())
//                 .collect::<Vec<_>>()
//                 .as_slice(),
//         );

//         let stream = r.make_stream(0.into()).unwrap();

//         let tpb = glwe.dim.polynomial_degree.threads_per_block();
//         let threads = tpb * num_blocks as u32;
//         let grid = (threads, tpb);
//         let scratch = Scratch::new(r, grid).unwrap();

//         unsafe {
//             launch_kernel!(
//                 (grid)
//                 ("can_glwe_ggsw_mad")
//                 (r, stream)
//                 c,
//                 a,
//                 b,
//                 scratch
//             )
//         }
//         .unwrap();

//         stream.wait().unwrap();

//         for i in 0..num_blocks {
//             let actual_fft = c
//                 .as_slice()
//                 .chunks(GlweCiphertextFftRef::size(glwe.dim))
//                 .nth(i)
//                 .unwrap();
//             let actual_fft = GlweCiphertextFftRef::from_slice(actual_fft);
//             let mut actual = GlweCiphertext::<u64>::new(&glwe);
//             actual_fft.ifft(&mut actual, &glwe);

//             let actual = sk.decrypt_decode_glwe(&actual, &glwe, PlaintextBits(1));

//             assert_eq!(actual.coeffs()[0], (c_msg[i] + a_msg[i] * b_msg[i]) % 2);

//             for i in 1..glwe.dim.polynomial_degree.0 {
//                 assert_eq!(actual.coeffs()[i], 0);
//             }
//         }
//     }
// }

// #[test]
// fn can_cmux() {
//     let runtimes = get_runtimes();
//     let num_blocks = 100;

//     let radix = RadixDecomposition {
//         count: RadixCount(2),
//         radix_log: RadixLog(16),
//     };

//     let glwe = GLWE_1_2048_128;

//     for r in runtimes.iter() {
//         let sk = GlweSecretKey::generate_binary(&glwe);

//         let a_msg = (0..num_blocks)
//             .map(|_| rng().next_u64() % 2)
//             .collect::<Vec<_>>();
//         let a_glwe = a_msg
//             .iter()
//             .map(|x| {
//                 let mut msg = Polynomial::zero(glwe.dim.polynomial_degree.0);
//                 msg.coeffs_mut()[0] = *x;

//                 sk.encode_encrypt_glwe(&msg, &glwe, PlaintextBits(1))
//             })
//             .collect::<Vec<_>>();

//         let b_msg = (0..num_blocks)
//             .map(|_| rng().next_u64() % 2)
//             .collect::<Vec<_>>();
//         let b_glwe = b_msg
//             .iter()
//             .map(|x| {
//                 let mut msg = Polynomial::zero(glwe.dim.polynomial_degree.0);
//                 msg.coeffs_mut()[0] = *x;

//                 sk.encode_encrypt_glwe(&msg, &glwe, PlaintextBits(1))
//             })
//             .collect::<Vec<_>>();

//         let sel_msg = (0..num_blocks)
//             .map(|_| rng().next_u64() % 2)
//             .collect::<Vec<_>>();

//         let sel_ggsw_fft = sel_msg
//             .iter()
//             .map(|x| {
//                 let mut msg = Polynomial::zero(glwe.dim.polynomial_degree.0);
//                 msg.coeffs_mut()[0] = *x;

//                 let ct = sk.encode_encrypt_ggsw(&msg, &glwe, &radix, PlaintextBits(1));
//                 high_level::fft::fft_ggsw(&ct, &glwe, &radix)
//             })
//             .collect::<Vec<_>>();

//         let mut c = r
//             .allocate::<Torus<u64>>(num_blocks * GlweCiphertextRef::<u64>::size(glwe.dim))
//             .unwrap();
//         let mut a = r
//             .allocate::<Torus<u64>>(num_blocks * GlweCiphertextRef::<u64>::size(glwe.dim))
//             .unwrap();
//         let mut b = r
//             .allocate::<Torus<u64>>(num_blocks * GlweCiphertextRef::<u64>::size(glwe.dim))
//             .unwrap();
//         let mut sel = r
//             .allocate::<Complex<f64>>(
//                 num_blocks * GgswCiphertextFftRef::<Complex<f64>>::size((glwe.dim, radix.count)),
//             )
//             .unwrap();

//         c.as_mut_slice().clone_from_slice(&vec![
//             Torus::from(0);
//             num_blocks
//                 * GlweCiphertextRef::<u64>::size(glwe.dim)
//         ]);
//         a.as_mut_slice().clone_from_slice(
//             a_glwe
//                 .iter()
//                 .flat_map(|x| x.as_slice().to_vec())
//                 .collect::<Vec<_>>()
//                 .as_slice(),
//         );
//         b.as_mut_slice().clone_from_slice(
//             b_glwe
//                 .iter()
//                 .flat_map(|x| x.as_slice().to_vec())
//                 .collect::<Vec<_>>()
//                 .as_slice(),
//         );
//         sel.as_mut_slice().clone_from_slice(
//             sel_ggsw_fft
//                 .iter()
//                 .flat_map(|x| x.as_slice().to_vec())
//                 .collect::<Vec<_>>()
//                 .as_slice(),
//         );

//         let stream = r.make_stream(0.into()).unwrap();

//         let tpb = glwe.dim.polynomial_degree.threads_per_block();
//         let threads = tpb * num_blocks as u32;
//         let grid = (threads, tpb);
//         let scratch = Scratch::new(r, grid).unwrap();

//         unsafe {
//             launch_kernel!(
//                 (grid)
//                 ("can_cmux")
//                 (r, stream)
//                 c,
//                 a,
//                 b,
//                 sel,
//                 scratch
//             )
//         }
//         .unwrap();

//         stream.wait().unwrap();

//         for i in 0..num_blocks {
//             let actual = c
//                 .as_slice()
//                 .chunks(GlweCiphertextRef::<u64>::size(glwe.dim))
//                 .nth(i)
//                 .unwrap();
//             let actual = GlweCiphertextRef::from_slice(actual);

//             let mut debug = Polynomial::<Torus<u64>>::zero(glwe.dim.polynomial_degree.0);
//             decrypt_glwe_ciphertext(&mut debug, actual, &sk, &glwe);

//             let actual = sk.decrypt_decode_glwe(&actual, &glwe, PlaintextBits(1));

//             let c = actual.coeffs()[0];
//             let sel = sel_msg[i];
//             let a = a_msg[i];
//             let b = b_msg[i];

//             assert_eq!(
//                 c,
//                 if sel == 1 { b } else { a },
//                 "i={i} c={c} sel={sel} a={a} b={b}"
//             );

//             for i in 1..glwe.dim.polynomial_degree.0 {
//                 if actual.coeffs()[i] != 0 {
//                     dbg!(i, debug.coeffs()[i]);
//                 }

//                 assert_eq!(actual.coeffs()[i], 0);
//             }
//         }
//     }
// }
