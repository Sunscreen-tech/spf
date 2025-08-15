use num::Complex;
use rand::{RngCore, rng};
use sunscreen_gpu_runtime::launch_kernel;

use crate::{
    entities::{DstArray, Polynomial}, gpu::{get_runtimes, tests::test_utils::fill_complex_rand_mod}, simd::VectorOps, PolynomialDegree
};

#[test]
fn can_mod_2_pow_64() {
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        let num_values = 2048;
        let degree = PolynomialDegree(num_values * num_blocks);

        // Using polynomial as a big array. Don't read much more into the type than that.
        let mut data = DstArray::<Polynomial<f64>>::new(1, degree);
        let actual = DstArray::<Polynomial<u64>>::new(1, degree);

        for c in data.iter_mut(degree).nth(0).unwrap().coeffs_mut() {
            let sign = if rng().next_u64() % 2 == 0 { 1.0 } else { -1.0 };

            // Produces a value on the order of 1e29
            *c = sign * rng().next_u64() as f64 * rng().next_u32() as f64;
        }

        let data_orig = data.clone();

        let stream = r.make_stream(0.into()).unwrap();

        let threads_per_block = 128;
        let n = degree.0 as u32;

        unsafe {
            launch_kernel!(
                ((threads_per_block, threads_per_block))
                ("can_reduce_mod_2_pow_64")
                (r, stream)
                data,
                actual,
                n
            )
        }
        .unwrap();

        stream.wait().unwrap();

        let (actual, data_orig) = (
            actual.iter(degree).nth(0).unwrap().coeffs(),
            data_orig.iter(degree).nth(0).unwrap().coeffs(),
        );

        let mut expected = vec![0u64; degree.0];

        VectorOps::vector_mod_pow2_q_f64(&mut expected, data_orig, 64);

        assert_eq!(actual, expected.as_slice());
    }
}

#[test]
fn can_complex_mad() {
    let runtimes = get_runtimes();
    for r in runtimes.iter() {
        let degree = PolynomialDegree(2048 * 128);

        let mut c = DstArray::<Polynomial<Complex<f64>>>::new(1, degree);
        let mut a = DstArray::<Polynomial<Complex<f64>>>::new(1, degree);
        let mut b = DstArray::<Polynomial<Complex<f64>>>::new(1, degree);

        fill_complex_rand_mod(c.iter_mut(degree).nth(0).unwrap().coeffs_mut(), 2.0f64.powf(64.0f64));
        fill_complex_rand_mod(a.iter_mut(degree).nth(0).unwrap().coeffs_mut(), 2.0f64.powf(64.0f64));
        fill_complex_rand_mod(b.iter_mut(degree).nth(0).unwrap().coeffs_mut(), 2.0f64.powf(16.0f64));

        let c_orig = c.clone();

        let stream = r.make_stream(0.into()).unwrap();

        let threads_per_block = 128;
        let n = degree.0 as u32;

        unsafe {
            launch_kernel!(
                ((threads_per_block, threads_per_block))
                ("can_complex_mad")
                (r, stream)
                c,
                a,
                b,
                n
            )
        }
        .unwrap();

        stream.wait().unwrap();

        let (actual, c_orig, a, b) = (
            c.iter(degree).nth(0).unwrap().coeffs(),
            c_orig.iter(degree).nth(0).unwrap().coeffs(),
            a.iter(degree).nth(0).unwrap().coeffs(),
            b.iter(degree).nth(0).unwrap().coeffs(),
        );

        for i in 0..n as usize {
            let expected = c_orig[i] + a[i] * b[i];
            approx::assert_relative_eq!(actual[i].re, expected.re, max_relative = 1e-10);
            approx::assert_relative_eq!(actual[i].im, expected.im, max_relative = 1e-10);
        }
    }
}
