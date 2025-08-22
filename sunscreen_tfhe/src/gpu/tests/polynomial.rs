use std::num::Wrapping;

use approx::Relative;
use num::{Complex, Zero};
use rand::{Rng, rng};
use sunscreen_gpu_runtime::launch_kernel;

use crate::{
    PolynomialDegree,
    dst::{AsMutSlice, AsSlice},
    entities::{DstArray, DstArrayRef, Polynomial, PolynomialFft, PolynomialRef},
    gpu::{
        Scratch, get_runtimes,
        test_utils::SUPPORTED_POLY_DEGREES,
        tests::{
            test_utils::{
                constant_poly, fill_complex_rand_mod, glwe_encrypt, random_complex_poly_mod,
                random_complex_polyfft_mod, random_poly_mod, random_poly_mod_2_pow_64,
            },
            ulps_difference,
        },
    },
    high_level,
    polynomial::{polynomial_add, polynomial_mad, polynomial_sub},
};

/// Naively compute the product of two polynomials in C[X].
pub fn polynomial_mul_complex(
    c: &mut PolynomialRef<Complex<f64>>,
    a: &PolynomialRef<Complex<f64>>,
    b: &PolynomialRef<Complex<f64>>,
) {
    assert!(a.len().is_power_of_two());
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), c.len());

    let len: usize = a.len();
    let coeffs = c.coeffs_mut();

    for (i, l) in a.coeffs().iter().copied().take(len).enumerate() {
        for (j, r) in b.coeffs().iter().copied().take(len).enumerate() {
            if i >= a.len() / 2 {
                assert_eq!(l, Complex::zero());
            }

            if j >= b.len() / 2 {
                assert_eq!(r, Complex::zero());
            }

            let index = i + j;
            if index < a.len() {
                coeffs[index] = coeffs[index] + l * r;
            }
        }
    }
}

#[test]
pub fn inplace_vs_out_of_place_fft() {
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let mut input = DstArray::<Polynomial<u64>>::new(num_blocks, d);
            let inplace = DstArray::<PolynomialFft<Complex<f64>>>::new(num_blocks, d);
            let out_of_place = inplace.clone();

            // Do something representative of a base decomposition.
            // a and c are random over the full u64, while b is over 16-bit integers
            random_poly_mod_2_pow_64(&mut input, &d);

            let stream = r.make_stream(0.into()).unwrap();
            let threads_per_block = d.threads_per_block();
            let num_threads = num_blocks as u32 * threads_per_block;
            let grid = (num_threads, threads_per_block);

            unsafe {
                launch_kernel!(
                    (grid)
                    ("inplace_vs_out_of_place_fft")
                    (r, stream)
                    out_of_place,
                    inplace,
                    input,
                    d.0 as u32
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for (ip, oop) in inplace.iter(d).zip(out_of_place.iter(d)) {
                assert_eq!(ip.coeffs(), oop.coeffs());
            }
        }
    }
}

#[test]
pub fn inplace_vs_out_of_place_ifft() {
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let mut input = DstArray::<PolynomialFft<Complex<f64>>>::new(num_blocks, d);
            let inplace = DstArray::<Polynomial<u64>>::new(num_blocks, d);
            let out_of_place = inplace.clone();

            // Do something representative of a base decomposition.
            // a and c are random over the full u64, while b is over 16-bit integers
            random_complex_polyfft_mod(&mut input, &d, 2.0f64.powf(64.0));

            let stream = r.make_stream(0.into()).unwrap();
            let threads_per_block = d.threads_per_block();
            let num_threads = num_blocks as u32 * threads_per_block;
            let grid = (num_threads, threads_per_block);

            unsafe {
                launch_kernel!(
                    (grid)
                    ("inplace_vs_out_of_place_ifft")
                    (r, stream)
                    out_of_place,
                    inplace,
                    input,
                    d.0 as u32
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for (ip, oop) in inplace.iter(d).zip(out_of_place.iter(d)) {
                assert_eq!(ip.coeffs(), oop.coeffs());
            }
        }
    }
}

#[test]
pub fn naive_complex_poly_multiply() {
    let mut a = Polynomial::<Complex<f64>>::zero(8);
    let mut b = Polynomial::<Complex<f64>>::zero(8);
    let mut c = Polynomial::<Complex<f64>>::zero(8);

    for i in 1..=4 {
        a.coeffs_mut()[i - 1] = Complex::new(i as f64, (i * 2) as f64);
        b.coeffs_mut()[i - 1] = Complex::new((i * 3) as f64, (i * 4) as f64);
    }

    polynomial_mul_complex(&mut c, &a, &b);

    // Computed with Wolfram Alpha
    let expected = Polynomial::<Complex<f64>>::new(&[
        Complex::new(-5.0, 10.0),  // x^0
        Complex::new(-20.0, 40.0), // x^1
        Complex::new(-50.0, 100.0),
        Complex::new(-100.0, 200.0),
        Complex::new(-125.0, 250.0),
        Complex::new(-120.0, 240.0),
        Complex::new(-80.0, 160.0),
        Complex::new(0.0, 0.0),
    ]);

    assert_eq!(expected.coeffs(), c.coeffs());
}

fn polynomial_roundtrip_test(kernel: &str) {
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let mut x = DstArray::<Polynomial<u64>>::new(num_blocks, d);
            let y = x.clone();

            random_poly_mod(&mut x, &d, 0x1 << 48);

            let stream = r.make_stream(0.into()).unwrap();

            let threads_per_block = d.threads_per_block();
            let num_threads = num_blocks as u32 * threads_per_block;

            let grid = (num_threads, threads_per_block);
            let scratch = Scratch::new(r, grid).unwrap();

            unsafe {
                launch_kernel!(
                    (grid)
                    (kernel)
                    (r, stream)
                    x,
                    y,
                    scratch,
                    d.0 as u32
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for (a, e) in x.iter(d).zip(y.iter(d)) {
                assert_eq!(a.coeffs(), e.coeffs());
            }
        }
    }
}

#[test]
fn can_roundtrip_polynomial() {
    polynomial_roundtrip_test("can_polynomial_rountrip_fft");
}

#[test]
fn can_roundtrip_polynomial_inplace() {
    polynomial_roundtrip_test("can_polynomial_rountrip_fft_inplace");
}

fn poly_op_test<F>(baseline_op: F, kernel_name: &str)
where
    F: Fn(&mut PolynomialRef<u64>, &PolynomialRef<u64>, &PolynomialRef<u64>),
{
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let c = DstArray::<Polynomial<u64>>::new(num_blocks, d);
            let mut a = c.clone();
            let mut b = c.clone();

            random_poly_mod_2_pow_64(&mut a, &d);
            random_poly_mod_2_pow_64(&mut b, &d);

            let stream = r.make_stream(0usize.into()).unwrap();
            let threads_per_block = d.threads_per_block();
            let num_threads = num_blocks as u32 * threads_per_block;

            unsafe {
                launch_kernel!(
                    ((num_threads, threads_per_block))
                    (kernel_name)
                    (r, stream)
                    c,
                    a,
                    b,
                    d.0 as u32
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for ((c, a), b) in c.iter(d).zip(a.iter(d)).zip(b.iter(d)) {
                let mut expected = Polynomial::<u64>::zero(d.0);

                baseline_op(&mut expected, a, b);

                assert_eq!(c.as_slice(), expected.as_slice());
            }
        }
    }
}

#[test]
fn can_sub_polynomials() {
    poly_op_test(|c, a, b| polynomial_sub(c, a, b), "can_sub_polynomials");
}

#[test]
fn can_add_polynomials() {
    poly_op_test(|c, a, b| polynomial_add(c, a, b), "can_add_polynomials");
}

#[ignore]
#[test]
fn can_multiply_non_negacyclic_polynomials() {
    let runtimes = get_runtimes();
    let num_blocks = 1;

    for r in runtimes.iter() {
        let d = PolynomialDegree(1024);
        let c = DstArray::<Polynomial<Complex<f64>>>::new(num_blocks, d);
        let mut a: DstArray<Polynomial<Complex<f64>>> = c.clone();
        let mut b = c.clone();

        let fill_half = |x: &mut DstArrayRef<PolynomialRef<Complex<f64>>>, modulus| {
            for poly in x.iter_mut(d) {
                let split = d.0 / 2;

                for c in poly.coeffs_mut().iter_mut().take(split) {
                    c.re = 2.0 * modulus * (rng().random::<f64>() - 0.5);
                    c.im = 2.0 * modulus * (rng().random::<f64>() - 0.5);
                }
            }
        };

        // We're multiplying 2 degree N/2 polynomials and producing a degree N polynomial.
        // I.e. no modulo reduction over X^N + 1.
        // So we only fill the first N/2 coefficients.
        //
        // As for the coefficients, simulate multiplying torus polynomial times a 16-bit
        // radix term.
        fill_half(&mut a, 2.0f64.powf(64.0));
        fill_half(&mut b, 2.0f64.powf(16.0));

        let stream = r.make_stream(0.into()).unwrap();

        // Times 2 because we're doing a full-width FFT, not negacyclic.
        let threads_per_block = d.threads_per_block() * 2;
        let num_threads = num_blocks as u32 * threads_per_block;
        let grid = (num_threads, threads_per_block);

        unsafe {
            launch_kernel!(
                (grid)
                ("can_multiply_non_negacyclic_polynomials")
                (r, stream)
                c,
                a,
                b,
                d.0 as u32
            )
        }
        .unwrap();

        stream.wait().unwrap();

        let n_inv = 1.0f64 / d.0 as f64;

        for ((actual, a), b) in c.iter(d).zip(a.iter(d)).zip(b.iter(d)) {
            let mut expected = Polynomial::zero(d.0);

            polynomial_mul_complex(&mut expected, a, b);

            for (i, (a, e)) in actual
                .coeffs()
                .iter()
                .zip(expected.coeffs().iter())
                .enumerate()
            {
                if i == 1023 {
                    // In the exact computation, these coefficients are exactly zero. However,
                    // our input numbers are huge, so we do wind up with non-trivial
                    // ~30-bit values in the zero terms after doing our FFT-based convolution.
                    // Simply assert these values are less than 34-bits to ensure this value
                    // is just numerical noise compared to our non-zero results, which
                    // are orders of magnitude larger.
                    assert!((a.re * n_inv).abs().log2() < 34.0);
                    assert!((a.im * n_inv).abs().log2() < 34.0);
                } else {
                    approx::assert_relative_eq!(
                        a.re * n_inv,
                        e.re,
                        max_relative = 1e-10,
                        epsilon = 1e-10
                    );
                    approx::assert_relative_eq!(
                        a.im * n_inv,
                        e.im,
                        max_relative = 1e-10,
                        epsilon = 1e-10
                    );
                }
            }
        }
    }
}

#[test]
fn can_mad_pre_fftd_polynomials() {
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let mut c = DstArray::<Polynomial<u64>>::new(num_blocks, d);
            let mut a = c.clone();
            let mut b = c.clone();

            // Do something representative of a base decomposition.
            // a and c are random over the full u64, while b is over 16-bit integers
            random_poly_mod(&mut c, &d, 0x1 << 18);
            random_poly_mod_2_pow_64(&mut a, &d);
            random_poly_mod(&mut b, &d, 0x1 << 16);

            let mut c_fft = DstArray::<PolynomialFft<Complex<f64>>>::new(num_blocks, d);
            let mut a_fft = c_fft.clone();
            let mut b_fft = c_fft.clone();

            for i in 0..num_blocks {
                c.iter(d)
                    .nth(i)
                    .unwrap()
                    .fft(c_fft.iter_mut(d).nth(i).unwrap());
                a.iter(d)
                    .nth(i)
                    .unwrap()
                    .fft(a_fft.iter_mut(d).nth(i).unwrap());

                b.iter(d)
                    .nth(i)
                    .unwrap()
                    .fft(b_fft.iter_mut(d).nth(i).unwrap());
            }

            let mut c_fft_orig = c_fft.clone();

            let stream = r.make_stream(0.into()).unwrap();
            let threads_per_block = d.threads_per_block();
            let num_threads = num_blocks as u32 * threads_per_block;
            let grid = (num_threads, threads_per_block);

            unsafe {
                launch_kernel!(
                    (grid)
                    ("can_mad_polynomials_pre_fftd")
                    (r, stream)
                    c_fft,
                    a_fft,
                    b_fft,
                    d.0 as u32
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for i in 0..num_blocks {
                let actual_fft = c_fft.iter(d).nth(i).unwrap();
                let mut actual = Polynomial::<u64>::zero(d.0);
                actual_fft.ifft(&mut actual);

                let c_fft = c_fft_orig.iter_mut(d).nth(i).unwrap();
                let a_fft = a_fft.iter(d).nth(i).unwrap();
                let b_fft = b_fft.iter(d).nth(i).unwrap();

                c_fft.multiply_add(a_fft, b_fft);

                let mut expected = Polynomial::<u64>::zero(d.0);
                c_fft.ifft(&mut expected);

                for (a, e) in actual.coeffs().iter().zip(expected.coeffs().iter()) {
                    approx::assert_relative_eq!(*a as f64, *e as f64, max_relative = 1e-3);
                }
            }
        }
    }
}

fn polynomial_mad_case(kernel_name: &str) {
    let runtimes = get_runtimes();
    let num_blocks = 1;

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let result = DstArray::<Polynomial<f64>>::new(num_blocks, d);

            let mut c = DstArray::<Polynomial<u64>>::new(num_blocks, d);
            let mut a = c.clone();
            let mut b = c.clone();

            // Do something representative of a base decomposition.
            // a and c are random over the full u64, while b is over 16-bit integers
            // random_poly_mod_2_pow_64(&mut c, &d);
            // random_poly_mod_2_pow_64(&mut a, &d);
            // random_poly_mod(&mut b, &d, 0x1 << 16);
            constant_poly(&mut c, &d, 0xFFFFFFFFFFFFFFFF);
            constant_poly(&mut a, &d, 69);
            constant_poly(&mut b, &d, 38);

            let c_orig = c.clone();

            let stream = r.make_stream(0.into()).unwrap();
            let threads_per_block = d.threads_per_block();
            let num_threads = num_blocks as u32 * threads_per_block;
            let grid = (num_threads, threads_per_block);

            let scratch = Scratch::new(r, grid).unwrap();

            unsafe {
                launch_kernel!(
                    (grid)
                    (kernel_name)
                    (r, stream)
                    result,
                    c,
                    a,
                    b,
                    scratch,
                    d.0 as u32
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for i in 0..num_blocks {
                let c_orig = c_orig.iter(d).nth(i).unwrap();
                let a = a.iter(d).nth(i).unwrap();
                let b = b.iter(d).nth(i).unwrap();

                let mut c_fft = high_level::fft::fft_polynomial(&c_orig, &d);
                let a_fft = high_level::fft::fft_polynomial(&a, &d);
                let b_fft = high_level::fft::fft_polynomial(&b, &d);

                let actual = c.iter(d).nth(i).unwrap();

                c_fft.multiply_add(&a_fft, &b_fft);

                let mut expected = Polynomial::<u64>::zero(d.0);
                c_fft.ifft(&mut expected);

                for (a, e) in actual.coeffs().iter().zip(expected.coeffs().iter()) {
                    approx::assert_relative_eq!(*a as f64, *e as f64, max_relative = 1e-4);
                }
            }
        }
    }
}

#[test]
fn can_mad_polynomials() {
    polynomial_mad_case("can_mad_polynomials");
}

#[test]
fn can_mad_polynomials_inplace() {
    polynomial_mad_case("can_mad_polynomials_inplace");
}

#[ignore]
#[test]
fn analyze_polynomial_mad() {
    let runtimes = get_runtimes();
    let num_blocks = 1024;

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let result = DstArray::<Polynomial<f64>>::new(num_blocks, d);

            let mut c = DstArray::<Polynomial<u64>>::new(num_blocks, d);
            let mut a = c.clone();
            let mut b = c.clone();

            // Do something representative of a base decomposition.
            // a and c are random over the full u64, while b is over 16-bit integers
            // random_poly_mod_2_pow_64(&mut c, &d);
            // Our input is 2^18 to account for us summing like 4 polynomials in a
            // CMUX.
            random_poly_mod(&mut c, &d, 0x1 << 18);
            random_poly_mod_2_pow_64(&mut a, &d);
            random_poly_mod(&mut b, &d, 0x1 << 16);

            let c_orig = c.clone();

            let stream = r.make_stream(0.into()).unwrap();
            let threads_per_block = d.threads_per_block();
            let num_threads = num_blocks as u32 * threads_per_block;
            let grid = (num_threads, threads_per_block);

            let scratch = Scratch::new(r, grid).unwrap();

            unsafe {
                launch_kernel!(
                    (grid)
                    ("can_mad_polynomials")
                    (r, stream)
                    result,
                    c,
                    a,
                    b,
                    scratch,
                    d.0 as u32
                )
            }
            .unwrap();

            stream.wait().unwrap();

            let mut relative_err_cpu = vec![0.0; d.0];
            let mut relative_err_gpu = vec![0.0; d.0];

            for i in 0..num_blocks {
                // Get the expected result doing the same negacyclic FFT convolution on the CPU.
                let c_orig = c_orig.iter(d).nth(i).unwrap();
                let a = a.iter(d).nth(i).unwrap();
                let b = b.iter(d).nth(i).unwrap();

                let mut c_fft = high_level::fft::fft_polynomial(&c_orig, &d);
                let a_fft = high_level::fft::fft_polynomial(&a, &d);
                let b_fft = high_level::fft::fft_polynomial(&b, &d);

                let gpu = c.iter(d).nth(i).unwrap();

                c_fft.multiply_add(&a_fft, &b_fft);

                let mut cpu_fft = Polynomial::<u64>::zero(d.0);
                c_fft.ifft(&mut cpu_fft);

                // Compute the true value using naive multiplication
                let mut cpu_exact = c_orig.map(|x| Wrapping(*x));
                let a = a.map(|x| Wrapping(*x));
                let b = b.map(|x| Wrapping(*x));
                polynomial_mad(&mut cpu_exact, &a, &b);

                for (i, ((cpu_fft, gpu_fft), cpu_exact)) in gpu
                    .coeffs()
                    .iter()
                    .zip(cpu_fft.coeffs().iter())
                    .zip(cpu_exact.coeffs())
                    .enumerate()
                {
                    relative_err_cpu[i] +=
                        (*cpu_fft as f64 - (cpu_exact.0 as f64)).abs() / 2.0f64.powf(64.0);
                    relative_err_gpu[i] +=
                        (*gpu_fft as f64 - (cpu_exact.0 as f64)).abs() / 2.0f64.powf(64.0);
                }
            }

            // Print the mean error relative to exactly computed Torus elements.
            for i in 0..d.0 {
                println!(
                    "Coefficient {i}: CPU: {:e} GPU: {:e}",
                    relative_err_cpu[i] / num_blocks as f64,
                    relative_err_gpu[i] / num_blocks as f64
                );
            }

            panic!("Analysis complete.");
        }
    }
}
