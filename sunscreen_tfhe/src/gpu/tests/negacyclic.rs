use core::f64;

use num::{Complex, Zero};
use num_complex::ComplexFloat;
use rand::{RngCore, rng};
use sunscreen_gpu_runtime::{GpuRuntime, launch_kernel};

use crate::{
    FrequencyTransform, PolynomialDegree,
    entities::{DstArray, Polynomial, PolynomialFft},
    fft::negacyclic,
    gpu::{
        get_runtimes,
        test_utils::SUPPORTED_POLY_DEGREES,
        tests::{get_inv_twisty, get_shared_memory_bytes, get_twisty},
    },
};

// We don't have any forward or reverse tests because we have different re-ordering semantics
// between CPU and GPU. This functionality is covered by negacyclic polynomial multiplication
// tests.

#[test]
fn can_apply_twist() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for n in SUPPORTED_POLY_DEGREES.iter().copied() {
            let num_blocks = 19;

            let mut x = DstArray::<Polynomial<f64>>::new(num_blocks, n);
            let result = DstArray::<PolynomialFft<Complex<f64>>>::new(num_blocks, n);

            for x in x.iter_mut(n) {
                for c in x.coeffs_mut().iter_mut() {
                    *c = rng().next_u64() as f64;
                }
            }

            let stream = r.make_stream(0.into()).unwrap();
            let threads_per_block = n.threads_per_block();
            let num_threads = num_blocks as u32 * threads_per_block;

            unsafe {
                launch_kernel!(
                    ((num_threads, threads_per_block))
                    ("can_apply_twist")
                    (r, stream, get_shared_memory_bytes())
                    x,
                    result,
                    n.0 as u32
                )
            }
            .unwrap();

            stream.wait().unwrap();

            let n_div_2 = n.0 as usize / 2;

            for (x, result) in x.iter(n).zip(result.iter(n)) {
                let mut expected = vec![Complex::<f64>::zero(); n_div_2];

                for i in 0..n_div_2 {
                    let x = x.coeffs();
                    let e = Complex::new(x[i], x[i + n_div_2]);

                    expected[i] = e * get_twisty(i as u32, n.0 as u32);
                }

                for (e, a) in expected.iter().zip(result.coeffs().iter()) {
                    approx::assert_relative_eq!(a.re, e.re, max_relative = 1e-10);
                    approx::assert_relative_eq!(a.im, e.im, max_relative = 1e-10);
                }
            }
        }
    }
}

#[test]
fn can_remove_twist() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for n in SUPPORTED_POLY_DEGREES.iter().copied() {
            let num_blocks = 19;

            let mut x = DstArray::<PolynomialFft<Complex<f64>>>::new(num_blocks, n);
            let result = DstArray::<Polynomial<f64>>::new(num_blocks, n);

            for x in x.iter_mut(n) {
                for c in x.coeffs_mut().iter_mut() {
                    *c = Complex::new(rng().next_u64() as f64, rng().next_u64() as f64);
                }
            }

            let stream = r.make_stream(0.into()).unwrap();
            let threads_per_block = n.threads_per_block();
            let num_threads = num_blocks as u32 * threads_per_block;

            unsafe {
                launch_kernel!(
                    ((num_threads, threads_per_block))
                    ("can_remove_twist")
                    (r, stream, get_shared_memory_bytes())
                    x,
                    result,
                    n.0 as u32
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for (x, result) in x.iter(n).zip(result.iter(n)) {
                let mut expected = vec![f64::zero(); n.0];

                let n_div_2 = n.0 / 2;

                for i in 0..n_div_2 {
                    let x = x.coeffs();
                    let e = x[i] * get_inv_twisty(i as u32, n.0 as u32) / n_div_2 as f64;

                    expected[i] = e.re();
                    expected[i + n_div_2] = e.im();
                }

                for (e, a) in expected.iter().zip(result.coeffs().iter()) {
                    approx::assert_relative_eq!(a, e, max_relative = 1e-10);
                }
            }
        }
    }
}
