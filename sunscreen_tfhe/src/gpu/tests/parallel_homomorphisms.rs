use sunscreen_gpu_runtime::{DeviceId, launch_kernel_cg};

use crate::{
    GLWE_1_2048_128, PlaintextBits,
    entities::{DstArray, GlweCiphertext, Polynomial},
    gpu::{
        get_runtimes,
        tests::test_utils::{glwe_encrypt, random_msg},
    },
    high_level::keygen,
    ops::{ciphertext::glwe_add_assign, encryption::decrypt_glwe_ciphertext},
};

#[test]
fn can_reduce_glwe_dim_x() {
    let runtimes = get_runtimes();
    let glwe = GLWE_1_2048_128;

    let sk = keygen::generate_binary_glwe_sk(&glwe);

    for r in runtimes.iter() {
        for reduction_factor in [1, 2, 4, 8] {
            let base_count = reduction_factor;

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

            dbg!(reduction_factor);

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

                let mut dbg_e = Polynomial::zero(glwe.dim.polynomial_degree.0);
                decrypt_glwe_ciphertext(&mut dbg_e, &sum, &sk, &glwe);

                let expected = sk.decrypt_decode_glwe(&sum, &glwe, PlaintextBits(1));

                let actual = output.iter(glwe.dim).nth(i).unwrap();

                let mut dbg_a = Polynomial::zero(glwe.dim.polynomial_degree.0);
                decrypt_glwe_ciphertext(&mut dbg_a, &actual, &sk, &glwe);

                for (e, a) in dbg_e.coeffs().iter().zip(dbg_a.coeffs().iter()) {
                    //println!("{:0>64b} {:0>64b}", e.inner(), a.inner());
                }

                let actual = sk.decrypt_decode_glwe(&actual, &glwe, PlaintextBits(1));

                assert_eq!(actual, expected);
            }
        }
    }
}
