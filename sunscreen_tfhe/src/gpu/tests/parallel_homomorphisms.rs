use sunscreen_gpu_runtime::{DeviceId, launch_kernel_cg};

use crate::{
    GLWE_1_2048_128, GlweDef, PlaintextBits, RadixCount, RadixDecomposition, RadixLog, Torus,
    entities::{
        DstArray, GgswCiphertext, GlevCiphertext, GlweCiphertext, GlweCiphertextRef, GlweSecretKey,
        Polynomial,
    },
    gpu::{
        Scratch, get_runtimes,
        tests::test_utils::{
            ggsw_encrypt, glev_encrypt, glwe_encrypt, random_msg, random_torus_poly,
        },
    },
    high_level::keygen,
    normalized_torus_distance,
    ops::{
        ciphertext::{cmux, decomposed_polynomial_glev_mad, glwe_add_assign},
        encryption::decrypt_glwe_ciphertext,
    },
    radix::PolynomialRadixIterator,
};

#[test]
fn can_reduce_glwe_dim_x() {
    let runtimes = get_runtimes();
    let glwe = GLWE_1_2048_128;

    let sk = keygen::generate_binary_glwe_sk(&glwe);

    for r in runtimes.iter() {
        if r.get_device_attributes(DeviceId(0)).supports_cluster_groups == 0 {
            return;
        }

        for reduction_factor in [1, 2, 4, 8] {
            let base_count = 128;

            let mut input = DstArray::<GlweCiphertext<u64>>::new(base_count, glwe.dim);
            let output =
                DstArray::<GlweCiphertext<u64>>::new(base_count / reduction_factor, glwe.dim);

            glwe_encrypt(&mut input, random_msg, &sk, &glwe);

            let stream = r.make_stream(DeviceId(0)).unwrap();
            let tpb = glwe.dim.polynomial_degree.threads_per_block();
            let grid = (base_count as u32 * tpb, tpb);
            let cluster_grid = reduction_factor as u32;

            unsafe {
                launch_kernel_cg!(
                    (grid)
                    (cluster_grid)
                    ("can_reduce_glwe_fft_dim_x")
                    (r, stream, 64 * 1024)
                    output,
                    input
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for i in 0..base_count / reduction_factor {
                let mut sum = input
                    .iter(glwe.dim)
                    .nth(i * reduction_factor)
                    .unwrap()
                    .to_owned();

                for j in 1..reduction_factor {
                    let to_add = input
                        .iter(glwe.dim)
                        .nth(i * reduction_factor + j)
                        .unwrap()
                        .to_owned();

                    glwe_add_assign(&mut sum, &to_add, &glwe);
                }

                let expected = sk.decrypt_decode_glwe(&sum, &glwe, PlaintextBits(1));

                let actual = output.iter(glwe.dim).nth(i).unwrap();
                let actual = sk.decrypt_decode_glwe(&actual, &glwe, PlaintextBits(1));

                assert_eq!(actual, expected);
            }
        }
    }
}

#[test]
fn can_reduce_glwe_dim_y() {
    let runtimes = get_runtimes();
    let glwe = GLWE_1_2048_128;

    let sk = keygen::generate_binary_glwe_sk(&glwe);

    for r in runtimes.iter() {
        if r.get_device_attributes(DeviceId(0)).supports_cluster_groups == 0 {
            return;
        }

        for reduction_factor in [1, 2, 4, 8] {
            let base_count = 128;

            let mut input = DstArray::<GlweCiphertext<u64>>::new(base_count, glwe.dim);
            let output =
                DstArray::<GlweCiphertext<u64>>::new(base_count / reduction_factor, glwe.dim);

            glwe_encrypt(&mut input, random_msg, &sk, &glwe);

            let stream = r.make_stream(DeviceId(0)).unwrap();
            let tpb = glwe.dim.polynomial_degree.threads_per_block();
            let grid = ((tpb, tpb), (base_count as u32, 1));
            let cluster_grid = (1, reduction_factor as u32);

            unsafe {
                launch_kernel_cg!(
                    (grid)
                    (cluster_grid)
                    ("can_reduce_glwe_fft_dim_y")
                    (r, stream, 64 * 1024)
                    output,
                    input
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for i in 0..base_count / reduction_factor {
                let mut sum = input
                    .iter(glwe.dim)
                    .nth(i * reduction_factor)
                    .unwrap()
                    .to_owned();

                for j in 1..reduction_factor {
                    let to_add = input
                        .iter(glwe.dim)
                        .nth(i * reduction_factor + j)
                        .unwrap()
                        .to_owned();

                    glwe_add_assign(&mut sum, &to_add, &glwe);
                }

                let expected = sk.decrypt_decode_glwe(&sum, &glwe, PlaintextBits(1));

                let actual = output.iter(glwe.dim).nth(i).unwrap();
                let actual = sk.decrypt_decode_glwe(&actual, &glwe, PlaintextBits(1));

                assert_eq!(actual, expected);
            }
        }
    }
}

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

#[test]
fn can_parallel_polynomial_glev_mad() {
    let runtimes = get_runtimes();
    let num_blocks = 3;

    for r in runtimes.iter() {
        let radix = RadixDecomposition {
            count: RadixCount(2),
            radix_log: RadixLog(16),
        };

        let glwe = GLWE_1_2048_128;
        let sk = GlweSecretKey::generate_binary(&glwe);

        let c_glwe = DstArray::<GlweCiphertext<u64>>::new(num_blocks, glwe.dim);
        let mut a_poly =
            DstArray::<Polynomial<Torus<u64>>>::new(num_blocks, glwe.dim.polynomial_degree);
        let mut b_glev = DstArray::<GlevCiphertext<u64>>::new(num_blocks, (glwe.dim, radix.count));

        random_torus_poly(&mut a_poly, &glwe.dim.polynomial_degree);
        glev_encrypt(&mut b_glev, random_msg, &sk, &glwe, &radix);

        let c_orig = c_glwe.clone();

        let stream = r.make_stream(0.into()).unwrap();

        let tpb = glwe.dim.polynomial_degree.threads_per_block();
        let threads = tpb * num_blocks as u32;

        let grid = ((threads, tpb), (2, 1));
        let scratch = Scratch::new(r, grid).unwrap();

        unsafe {
            launch_kernel_cg!(
                (grid)
                ((1, 2))
                ("can_parallel_polynomial_glev_mad")
                (r, stream, 96 * 1024)
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
fn can_parallel_destructive_cmux() {
    let runtimes = get_runtimes();
    let num_blocks = 128;

    let radix = RadixDecomposition {
        count: RadixCount(2),
        radix_log: RadixLog(16),
    };

    let glwe = GLWE_1_2048_128;

    for r in runtimes.iter() {
        if r.get_device_attributes(DeviceId(0)).supports_cluster_groups == 0 {
            return;
        }

        let sk = GlweSecretKey::generate_binary(&glwe);

        let mut a_glwe = DstArray::<GlweCiphertext<u64>>::new(num_blocks, glwe.dim);
        let mut b_glwe = DstArray::<GlweCiphertext<u64>>::new(num_blocks, glwe.dim);
        let mut sel = DstArray::<GgswCiphertext<u64>>::new(num_blocks, (glwe.dim, radix.count));

        glwe_encrypt(&mut a_glwe, random_msg, &sk, &glwe);
        glwe_encrypt(&mut b_glwe, random_msg, &sk, &glwe);
        ggsw_encrypt(&mut sel, &sk, &glwe, &radix);

        let a_orig = a_glwe.clone();
        let b_orig = b_glwe.clone();

        let stream = r.make_stream(0.into()).unwrap();

        let tpb = glwe.dim.polynomial_degree.threads_per_block();
        let threads = tpb * num_blocks as u32;
        let grid = ((threads, tpb), (2, 1), (2, 1));
        let scratch = Scratch::new(r, grid).unwrap();

        unsafe {
            launch_kernel_cg!(
                (grid)
                ((1, 2, 2))
                ("can_parallel_destructive_cmux")
                (r, stream, 128 * 1024)
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
            let a = a_orig.iter(glwe.dim).nth(i).unwrap();
            let b = b_orig.iter(glwe.dim).nth(i).unwrap();
            let sel = sel.iter((glwe.dim, radix.count)).nth(i).unwrap();

            // Slow, but exact computation.
            cmux(&mut expected, a, b, sel, &glwe, &radix);

            let actual = a_glwe.iter(glwe.dim).nth(i).unwrap();

            compare_glwe_contents(&actual, &expected, glwe, &sk);
        }
    }
}
