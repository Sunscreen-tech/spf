use std::f64::consts::PI;

use num::{Complex, Float};
use sunscreen_gpu_runtime::launch_kernel;


use crate::{
    PolynomialDegree,
    entities::{DstArray, Polynomial},
    gpu::{get_runtimes, tests::ulps_difference},
};

#[derive(PartialEq)]
enum Direction {
    Forward,
    Inverse,
}

// Will use noreorder FFT variant if kernels compiled with -DFFT_NO_REORDER
#[test]
fn can_roundtrip_fft_f64() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        let n = 1024;
        let degree = PolynomialDegree(n as usize);

        let num_blocks = 19;

        // We're just using a polynomial as a simple array. Don't ascribe any meaning beyond that.
        let mut x = DstArray::<Polynomial<Complex<f64>>>::new(num_blocks, degree);
        let y = DstArray::<Polynomial<Complex<f64>>>::new(num_blocks, degree);

        for (i, x) in x.iter_mut(degree).enumerate() {
            for (j, c) in x.coeffs_mut().iter_mut().enumerate() {
                let i = i * n + j;

                *c = Complex::new(2.0 * i as f64, 2.0 * i as f64 + 1.0);
            }
        }

        let stream = r.make_stream(0.into()).unwrap();

        let threads_per_block = n as u32 / 4;
        let threads = num_blocks as u32 * threads_per_block;

        unsafe {
            launch_kernel! {
                ((threads, threads_per_block))
                ("can_roundtrip_fft_f64")
                (r, stream)
                x,
                y,
                n as u32
            }
        }
        .unwrap();

        stream.wait().unwrap();

        for (a, e) in x.iter(degree).zip(y.iter(degree)) {
            for (a, e) in a.coeffs().iter().zip(e.coeffs().iter()) {
                approx::assert_relative_eq!(a.re, e.re, max_relative = 1e-12, epsilon = 1e-12);
                approx::assert_relative_eq!(a.im, e.im, max_relative = 1e-12, epsilon = 1e-12);
            }
        }
    }
}

/// This test measures and prints the twiddle error against 4 different methods:
/// * Rust's sincos method
/// * The GPU's LUT
/// * The GPU's sincos method
/// * The GPU's sincospi method
///
/// To run it, enable the test and run `cargo test -- check_twiddles --nocapture`
#[ignore]
#[test]
fn check_twiddles() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for inverse in [false, true] {
            for n in [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
                println!("n={n} inv={inverse}");
                let degree = PolynomialDegree(n);

                // Use polynomials as arrays. Don't read into them any further than that.
                let lut = DstArray::<Polynomial<Complex<f64>>>::new(1, degree);
                let sincos = DstArray::<Polynomial<Complex<f64>>>::new(1, degree);
                let sincospi = DstArray::<Polynomial<Complex<f64>>>::new(1, degree);

                let stream = r.make_stream(0.into()).unwrap();

                let threads_per_block = 64;
                let num_threads = threads_per_block;

                unsafe {
                    launch_kernel!(
                        ((num_threads, threads_per_block))
                        ("get_twiddles_f64")
                        (r, stream)
                        lut,
                        sincos,
                        sincospi,
                        n as u32,
                        inverse as u32
                    )
                    .unwrap();
                }

                stream.wait().unwrap();

                let (lut, sincos, sincospi) = (
                    lut.iter(degree).nth(0).unwrap(),
                    sincos.iter(degree).nth(0).unwrap(),
                    sincospi.iter(degree).nth(0).unwrap(),
                );

                for (i, ((lut, sincos), sincospi)) in lut
                    .coeffs()
                    .iter()
                    .zip(sincos.coeffs().iter())
                    .zip(sincospi.coeffs().iter())
                    .enumerate()
                {
                    let factor = if inverse { 2.0 } else { -2.0 };

                    let x = rug::Float::with_val(256, factor * i as f64 / n as f64);

                    let sin = x.clone().sin_pi();
                    let cos = x.clone().cos_pi();

                    let actual_sin = sin.to_f64();
                    let actual_cos = cos.to_f64();

                    let (rust_sin, rust_cos) = f64::sin_cos(factor * PI * i as f64 / n as f64);

                    println!(
                        "\tsin({}2π{i}/{n}) rust_cpu={}ULPs LUT={}ULPs sincos={}ULPs sincospi={}ULPs",
                        if inverse { "-" } else { "" },
                        ulps_difference(rust_sin, actual_sin),
                        ulps_difference(lut.im, actual_sin),
                        ulps_difference(sincos.im, actual_sin),
                        ulps_difference(sincospi.im, actual_sin)
                    );

                    println!(
                        "\tcos({}2π{i}/{n}) rust_cpu={}ULPs LUT={}ULPs sincos={}ULPs sincospi={}ULPs",
                        if inverse { "-" } else { "" },
                        ulps_difference(rust_cos, actual_cos),
                        ulps_difference(lut.re, actual_cos),
                        ulps_difference(sincos.re, actual_cos),
                        ulps_difference(sincospi.re, actual_cos)
                    );
                }
            }
        }
    }
}
