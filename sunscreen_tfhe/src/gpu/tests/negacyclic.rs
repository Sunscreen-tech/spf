use core::f64;

use num::{Complex, Zero};
use num_complex::ComplexFloat;
use rand::{RngCore, thread_rng};
use sunscreen_gpu_runtime::launch_kernel;

use crate::{
    FrequencyTransform,
    fft::negacyclic,
    gpu::{
        test_utils::{SUPPORTED_POLY_DEGREES, get_runtimes},
        tests::{assert_complex_equalish, get_inv_twisty, get_twisty},
    },
};

#[test]
fn can_negacyclic_forward() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for n in [2048u32] {
            let num_ffts = 9;
            let num_points = num_ffts as usize * n as usize;

            let baseline_fft = negacyclic::get_fft(n.ilog2() as usize);

            let mut input = r.allocate::<f64>(num_points).unwrap();
            input.copy_from_slice(&(0..num_points).map(|x| x as f64).collect::<Vec<_>>());

            let output = r.allocate::<Complex<f64>>(num_points / 2).unwrap();

            let stream = r.make_stream().unwrap();

            let threads_per_block = n / 8;
            let num_threads = num_ffts as u32 * threads_per_block;

            unsafe {
                launch_kernel!(
                    ((num_threads, threads_per_block))
                    ("can_forward_twisted_fft_f64")
                    (r, stream, 0)
                    input,
                    output,
                    n
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for (input, actual) in input
                .as_slice()
                .chunks(n as usize)
                .zip(output.as_slice().chunks((n / 2) as usize))
            {
                let mut expected = vec![Complex::<f64>::zero(); n as usize];

                baseline_fft.forward(input, &mut expected);

                for (actual, expected) in actual.iter().zip(expected.iter()) {
                    assert_complex_equalish(actual, expected, 1e-9);
                }
            }
        }
    }
}

#[test]
fn can_negacyclic_inverse() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for n in [2048u32] {
            let num_ffts = 1;
            let num_points = num_ffts as usize * n as usize;

            let baseline_fft = negacyclic::get_fft(n.ilog2() as usize);

            let mut input = r.allocate::<Complex<f64>>(num_points / 2).unwrap();
            input.copy_from_slice(
                &(0..num_points / 2)
                    .map(|x| Complex::new(x as f64, -(x as f64)))
                    .collect::<Vec<_>>(),
            );

            let output = r.allocate::<f64>(num_points).unwrap();

            let stream = r.make_stream().unwrap();

            let threads_per_block = n / 8;
            let num_threads = num_ffts as u32 * threads_per_block;

            unsafe {
                launch_kernel!(
                    ((num_threads, threads_per_block))
                    ("can_inverse_twisted_fft_f64")
                    (r, stream, 0)
                    input,
                    output,
                    n
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for (input, actual) in input
                .as_slice()
                .chunks((n / 2) as usize)
                .zip(output.as_slice().chunks(n as usize))
            {
                let mut expected = vec![f64::zero(); n as usize];

                baseline_fft.reverse(input, &mut expected);

                for (actual, expected) in actual.iter().zip(expected.iter()) {
                    // Integral values may be off by up to 1 due to rounding...
                    assert!((actual - expected).abs() <= 1.0);
                }
            }
        }
    }
}

#[test]
fn can_apply_twist() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for n in SUPPORTED_POLY_DEGREES {
            let num_blocks = 19;

            let mut x = r.allocate::<f64>((num_blocks * n) as usize).unwrap();
            let result = r
                .allocate::<Complex<f64>>((num_blocks * n / 2) as usize)
                .unwrap();

            x.as_mut_slice()
                .iter_mut()
                .for_each(|x| *x = thread_rng().next_u64() as f64);

            let stream = r.make_stream().unwrap();
            let threads_per_block = n / 8;
            let num_threads = num_blocks * threads_per_block;

            unsafe {
                launch_kernel!(
                    ((num_threads, threads_per_block))
                    ("can_apply_twist")
                    (r, stream, 0)
                    x,
                    result,
                    *n
                )
            }
            .unwrap();

            stream.wait().unwrap();

            let n_div_2 = *n as usize / 2;

            let mut expected = vec![Complex::<f64>::zero(); n_div_2];

            for i in 0..n_div_2 {
                let x = x.as_slice();
                let e = Complex::new(x[i], x[i + n_div_2]);

                expected[i] = e * get_twisty(i as u32, *n);
            }

            for (a, e) in result.as_slice().iter().zip(expected.iter()) {
                dbg!((a, e));
                approx::assert_relative_eq!(a.re, e.re, max_relative = 1e-13);
                approx::assert_relative_eq!(a.im, e.im, max_relative = 1e-13);
            }
        }
    }
}

#[test]
fn can_remove_twist() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for n in SUPPORTED_POLY_DEGREES {
            let num_blocks = 19;

            let mut x = r
                .allocate::<Complex<f64>>((num_blocks * n / 2) as usize)
                .unwrap();
            let result = r.allocate::<f64>((num_blocks * n) as usize).unwrap();

            x.as_mut_slice().iter_mut().for_each(|x| {
                *x = Complex::new(
                    thread_rng().next_u64() as f64,
                    thread_rng().next_u64() as f64,
                )
            });

            let stream = r.make_stream().unwrap();
            let threads_per_block = n / 8;
            let num_threads = num_blocks * threads_per_block;

            unsafe {
                launch_kernel!(
                    ((num_threads, threads_per_block))
                    ("can_remove_twist")
                    (r, stream, 0)
                    x,
                    result,
                    *n
                )
            }
            .unwrap();

            stream.wait().unwrap();

            let n_div_2 = *n as usize / 2;

            let mut expected = vec![f64::zero(); *n as usize];

            for i in 0..n_div_2 {
                let x = x.as_slice();
                let e = x[i] * get_inv_twisty(i as u32, *n) / n_div_2 as f64;

                expected[i] = e.re();
                expected[i + n_div_2] = e.im();
            }

            for (a, e) in result.as_slice().iter().zip(expected.iter()) {
                dbg!((a, e));
                approx::assert_relative_eq!(a, e, max_relative = 1e-12);
            }
        }
    }
}

#[test]
fn can_negacyclic_roundtrip_noreorder() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for n in SUPPORTED_POLY_DEGREES {
            let num_blocks = 19;
            let len = (num_blocks * *n) as usize;

            let x = r.allocate::<Complex<f64>>(len).unwrap();
        }
    }
}
