use rand::rng;
use sunscreen_gpu_runtime::launch_kernel;

use crate::{
    GLWE_1_2048_128, GlweDef, PlaintextBits, RadixCount, RadixDecomposition, RadixLog, Torus,
    dst::AsSlice,
    entities::{
        DstArray, GgswCiphertext, GlevCiphertext, GlweCiphertext, GlweCiphertextRef, GlweSecretKey,
        Polynomial,
    },
    gpu::{
        Scratch, get_runtimes,
        test_utils::SUPPORTED_POLY_DEGREES,
        tests::test_utils::{
            ggsw_encrypt, glev_encrypt, glwe_encrypt, random_msg, random_poly_mod,
            random_torus_poly,
        },
    },
    high_level, normalized_torus_distance,
    ops::{
        ciphertext::{
            add_glwe_ciphertexts, cmux, decomposed_polynomial_glev_mad, glwe_ggsw_mad,
            sub_glwe_ciphertexts,
        },
        encryption::decrypt_glwe_ciphertext,
        fft_ops::glwe_polynomial_mad,
    },
    radix::PolynomialRadixIterator,
};

fn compare_glwe_contents(
    actual: &GlweCiphertextRef<u64>,
    expected: &GlweCiphertextRef<u64>,
    glwe: GlweDef,
    sk: &GlweSecretKey<u64>,
) {
    //Check the baseline and our GPU version encrypt the same messages.
    let mut expected_msg = Polynomial::zero(glwe.dim.polynomial_degree.0);
    decrypt_glwe_ciphertext(&mut expected_msg, &expected, &sk, &glwe);

    let mut actual_msg = Polynomial::zero(glwe.dim.polynomial_degree.0);
    decrypt_glwe_ciphertext(&mut actual_msg, &actual, &sk, &glwe);

    for (i, (a, e)) in actual_msg
        .coeffs()
        .iter()
        .zip(expected_msg.coeffs().iter())
        .enumerate()
    {
        let distance = normalized_torus_distance(a, e);
        let tolerance = 1e-6;

        assert!(
            distance < tolerance,
            "Torus element {i}: distance between {} and {} is {:e}, which is greater than {tolerance:e}",
            a.inner(),
            e.inner(),
            distance
        );
    }
}

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

#[test]
fn can_polynomial_glev_mad() {
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        let radix = RadixDecomposition {
            count: RadixCount(2),
            radix_log: RadixLog(16),
        };

        let glwe = GLWE_1_2048_128;
        let sk = GlweSecretKey::generate_binary(&glwe);

        let mut c_glwe = DstArray::<GlweCiphertext<u64>>::new(num_blocks, glwe.dim);
        let mut a_poly =
            DstArray::<Polynomial<Torus<u64>>>::new(num_blocks, glwe.dim.polynomial_degree);
        let mut b_glev = DstArray::<GlevCiphertext<u64>>::new(num_blocks, (glwe.dim, radix.count));

        glwe_encrypt(&mut c_glwe, random_msg, &sk, &glwe);
        random_torus_poly(&mut a_poly, &glwe.dim.polynomial_degree);
        glev_encrypt(&mut b_glev, random_msg, &sk, &glwe, &radix);

        let c_orig = c_glwe.clone();

        let stream = r.make_stream(0.into()).unwrap();

        let tpb = glwe.dim.polynomial_degree.threads_per_block();
        let threads = tpb * num_blocks as u32;

        let grid = (threads, tpb);
        let scratch = Scratch::new(r, grid).unwrap();

        unsafe {
            launch_kernel!(
                (grid)
                ("can_polynomial_glev_mad")
                (r, stream)
                c_glwe,
                a_poly,
                b_glev,
                scratch
            )
        }
        .unwrap();

        stream.wait().unwrap();

        for i in 0..num_blocks {
            // Compute the baseline on the CPU.
            let c_orig = c_orig.iter(glwe.dim).nth(i).unwrap();
            let a_poly = a_poly.iter(glwe.dim.polynomial_degree).nth(i).unwrap();
            let b_glev = b_glev.iter((glwe.dim, radix.count)).nth(i).unwrap();

            let mut expected = c_orig.to_owned();
            let mut scratch = Polynomial::zero(glwe.dim.polynomial_degree.0);
            let decomp = PolynomialRadixIterator::new(&a_poly, &mut scratch, &radix);

            // Use the slow, but exact external product.
            decomposed_polynomial_glev_mad(&mut expected, decomp, b_glev, &glwe);

            //Check the baseline and our GPU version encrypt the same messages.
            let actual = c_glwe.iter(glwe.dim).nth(i).unwrap();

            compare_glwe_contents(actual, &expected, glwe, &sk);
        }
    }
}

#[test]
fn can_glwe_ggsw_mad() {
    let runtimes = get_runtimes();
    let num_blocks = 13;

    let radix = RadixDecomposition {
        count: RadixCount(2),
        radix_log: RadixLog(16),
    };

    let glwe = GLWE_1_2048_128;

    for r in runtimes.iter() {
        let sk = GlweSecretKey::generate_binary(&glwe);

        let mut c_glwe = DstArray::<GlweCiphertext<u64>>::new(num_blocks, glwe.dim);
        let mut a_glwe = DstArray::<GlweCiphertext<u64>>::new(num_blocks, glwe.dim);
        let mut b_ggsw = DstArray::<GgswCiphertext<u64>>::new(num_blocks, (glwe.dim, radix.count));

        glwe_encrypt(&mut c_glwe, random_msg, &sk, &glwe);
        glwe_encrypt(&mut a_glwe, random_msg, &sk, &glwe);
        ggsw_encrypt(&mut b_ggsw, &sk, &glwe, &radix);

        let c_orig = c_glwe.clone();

        let stream = r.make_stream(0.into()).unwrap();

        let tpb = glwe.dim.polynomial_degree.threads_per_block();
        let threads = tpb * num_blocks as u32;
        let grid = (threads, tpb);
        let scratch = Scratch::new(r, grid).unwrap();

        unsafe {
            launch_kernel!(
                (grid)
                ("can_glwe_ggsw_mad")
                (r, stream)
                c_glwe,
                a_glwe,
                b_ggsw,
                scratch
            )
        }
        .unwrap();

        stream.wait().unwrap();

        for i in 0..num_blocks {
            let c_orig = c_orig.iter(glwe.dim).nth(i).unwrap();
            let a_glwe = a_glwe.iter(glwe.dim).nth(i).unwrap();
            let b_ggsw = b_ggsw.iter((glwe.dim, radix.count)).nth(i).unwrap();

            let mut expected = c_orig.to_owned();

            // Do the slow, but exact external product.
            glwe_ggsw_mad(&mut expected, &a_glwe, b_ggsw, &glwe, &radix);

            //Check the baseline and our GPU version encrypt the same messages.
            let actual = c_glwe.iter(glwe.dim).nth(i).unwrap();

            compare_glwe_contents(actual, &expected, glwe, &sk);
        }
    }
}

#[test]
fn can_cmux() {
    let runtimes = get_runtimes();
    let num_blocks = 100;

    let radix = RadixDecomposition {
        count: RadixCount(2),
        radix_log: RadixLog(16),
    };

    let glwe = GLWE_1_2048_128;

    for r in runtimes.iter() {
        let sk = GlweSecretKey::generate_binary(&glwe);

        let c_glwe = DstArray::<GlweCiphertext<u64>>::new(num_blocks, glwe.dim);
        let mut a_glwe = DstArray::<GlweCiphertext<u64>>::new(num_blocks, glwe.dim);
        let mut b_glwe = DstArray::<GlweCiphertext<u64>>::new(num_blocks, glwe.dim);
        let mut sel = DstArray::<GgswCiphertext<u64>>::new(num_blocks, (glwe.dim, radix.count));

        glwe_encrypt(&mut a_glwe, random_msg, &sk, &glwe);
        glwe_encrypt(&mut b_glwe, random_msg, &sk, &glwe);
        ggsw_encrypt(&mut sel, &sk, &glwe, &radix);

        let stream = r.make_stream(0.into()).unwrap();

        let tpb = glwe.dim.polynomial_degree.threads_per_block();
        let threads = tpb * num_blocks as u32;
        let grid = (threads, tpb);
        let scratch = Scratch::new(r, grid).unwrap();

        unsafe {
            launch_kernel!(
                (grid)
                ("can_cmux")
                (r, stream)
                c_glwe,
                a_glwe,
                b_glwe,
                sel,
                scratch
            )
        }
        .unwrap();

        stream.wait().unwrap();

        for i in 0..num_blocks {
            let mut expected = GlweCiphertext::new(&glwe);
            let a = a_glwe.iter(glwe.dim).nth(i).unwrap();
            let b = b_glwe.iter(glwe.dim).nth(i).unwrap();
            let sel = sel.iter((glwe.dim, radix.count)).nth(i).unwrap();

            // Slow, but exact computation.
            cmux(&mut expected, a, b, sel, &glwe, &radix);

            let actual = c_glwe.iter(glwe.dim).nth(i).unwrap();
            
            compare_glwe_contents(&actual, &expected, glwe, &sk);
        }
    }
}
