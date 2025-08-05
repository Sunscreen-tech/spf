use rand::{RngCore, thread_rng};
use sunscreen_gpu_runtime::launch_kernel;

use crate::{FromF64, entities::Polynomial, gpu::test_utils::get_runtimes, simd::VectorOps};

#[test]
fn can_mod_2_pow_64() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        let num_values = 2048;

        let mut data = r.allocate::<f64>(num_values as usize).unwrap();
        let mut actual = r.allocate::<u64>(num_values as usize).unwrap();

        data.as_mut_slice().iter_mut().for_each(|x| {
            let a = thread_rng().next_u32() as f64;
            let b = thread_rng().next_u64() as f64;

            let sign = if thread_rng().next_u64() % 2 == 0 {
                1.0
            } else {
                -1.0
            };

            *x = sign * a * b;
        });

        let mut expected = Polynomial::zero(num_values);
        u64::vector_mod_pow2_q_f64(expected.coeffs_mut(), &data.as_slice(), 64);

        let stream = r.make_stream().unwrap();

        let threads_per_block = 128;

        unsafe {
            launch_kernel!(
                ((threads_per_block, threads_per_block))
                ("can_reduce_mod_2_pow_64")
                (r, stream, 0)
                data,
                actual,
                num_values as u32
            )
        }
        .unwrap();

        stream.wait().unwrap();

        for (a, e) in actual.as_slice().iter().zip(expected.coeffs().iter()) {
            assert_eq!(*a, *e);
        }
    }
}
