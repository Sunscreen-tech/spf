use std::f64::consts::PI;

use bytemuck::Pod;
use num::{Complex, Float, FromPrimitive, NumCast, Signed};
use sunscreen_gpu_runtime::launch_kernel;

use rustfft::FftPlanner;

use crate::gpu::{
    test_utils::get_runtimes,
    tests::{assert_complex_equalish, ulps_difference},
};

#[derive(PartialEq)]
enum Direction {
    Forward,
    Inverse,
}

fn can_fft_impl<T>(kernel_name: &str, eps: T, direction: Direction)
where
    T: Float
        + Pod
        + NumCast
        + std::fmt::Debug
        + FromPrimitive
        + Signed
        + Sync
        + Send
        + std::fmt::Display,
{
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for n in [1024] {
            let mut planner = FftPlanner::new();
            let fft = if let Direction::Forward = direction {
                planner.plan_fft_forward(n as usize)
            } else {
                planner.plan_fft_inverse(n as usize)
            };

            let num_ffts = 1u32;
            let num_values = n * num_ffts;

            let mut a_gpu = r.allocate::<Complex<T>>(num_values as usize).unwrap();

            let b_gpu = r.allocate::<Complex<T>>(num_values as usize).unwrap();

            let a_slice = a_gpu.as_mut_slice();

            a_slice.copy_from_slice(
                &(0..num_values)
                    .map(|x| {
                        Complex::new(
                            <T as NumCast>::from(x).unwrap(),
                            <T as NumCast>::from(num_values - x).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>(),
            );

            let stream = r.make_stream(0.into()).unwrap();

            let threads_per_block = n / 4;
            let num_threads = threads_per_block * num_ffts;

            unsafe {
                launch_kernel!(
                    ((num_threads, threads_per_block))
                    (kernel_name)
                    (r, stream)
                    a_gpu,
                    b_gpu,
                    n
                )
                .unwrap();
            }

            stream.wait().unwrap();

            for a in a_gpu.as_slice().chunks(n as usize) {
                let mut expected = a.to_vec();
                fft.process(&mut expected);

                for (actual, expected) in b_gpu.as_slice().iter().zip(expected.iter()) {
                    assert_complex_equalish(actual, expected, eps);
                }
            }
        }
    }
}

#[test]
fn can_fft_f64() {
    can_fft_impl::<f64>("can_fft_f64", 1e-10, Direction::Forward);
}

#[test]
fn can_fft_f32() {
    can_fft_impl::<f32>("can_fft_f32", 1e-2, Direction::Forward);
}

#[test]
fn can_ifft_f64() {
    can_fft_impl::<f64>("can_ifft_f64", 1e-10, Direction::Inverse);
}

#[test]
fn can_ifft_f32() {
    can_fft_impl::<f32>("can_ifft_f32", 1e-2, Direction::Inverse);
}

// Will use noreorder FFT variant if kernels compiled with -DFFT_NO_REORDER
#[test]
fn can_roundtrip_fft_f64() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        let n = 1024;

        let num_blocks = 19;

        let mut x = r.allocate::<Complex<f64>>(n * num_blocks).unwrap();
        let y = r.allocate::<Complex<f64>>(n * num_blocks).unwrap();

        x.as_mut_slice()
            .iter_mut()
            .enumerate()
            .for_each(|(i, x)| *x = Complex::new(2.0 * i as f64, 2.0 * i as f64 + 1.0));

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

        for (a, e) in x.as_slice().iter().zip(y.as_slice().iter()) {
            approx::assert_relative_eq!(a.re, e.re, max_relative = 1e-12);
            approx::assert_relative_eq!(a.im, e.im, max_relative = 1e-12);
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
                let lut = r.allocate::<Complex<f64>>(n as usize).unwrap();
                let sincos = r.allocate::<Complex<f64>>(n as usize).unwrap();
                let sincospi = r.allocate::<Complex<f64>>(n as usize).unwrap();

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
                        n,
                        inverse as u32
                    )
                    .unwrap();
                }

                stream.wait().unwrap();

                for (i, ((lut, sincos), sincospi)) in lut
                    .as_slice()
                    .iter()
                    .zip(sincos.as_slice().iter())
                    .zip(sincospi.as_slice().iter())
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
