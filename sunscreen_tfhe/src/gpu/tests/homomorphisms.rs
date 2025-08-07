use sunscreen_gpu_runtime::launch_kernel;

use crate::{
    GLWE_1_2048_128, GlweDef, OverlaySize, PlaintextBits, Torus,
    dst::AsSlice,
    entities::{GlweCiphertext, GlweCiphertextRef, GlweSecretKey, Polynomial},
    gpu::test_utils::{SUPPORTED_POLY_DEGREES, get_runtimes},
    ops::ciphertext::{add_glwe_ciphertexts, sub_glwe_ciphertexts},
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
