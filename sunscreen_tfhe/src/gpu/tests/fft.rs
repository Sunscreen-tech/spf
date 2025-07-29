use bytemuck::Pod;
use num::{Complex, Float, FromPrimitive, NumCast, Signed};
use sunscreen_gpu_runtime::launch_kernel;

use rustfft::FftPlanner;

use crate::gpu::{test_utils::get_runtimes, tests::assert_complex_equalish};

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
        for n in [1024, 2048] {
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

            let stream = r.make_stream().unwrap();

            let threads_per_block = n / 4;
            let num_threads = threads_per_block * num_ffts;

            unsafe {
                launch_kernel!(
                    ((num_threads, threads_per_block))
                    (kernel_name)
                    (r, stream, 0)
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
    can_fft_impl::<f64>("can_rountrip_fft_f64", 1e-10, Direction::Forward);
}

#[test]
fn can_fft_f32() {
    can_fft_impl::<f32>("can_rountrip_fft_f32", 1e-2, Direction::Forward);
}

#[test]
fn can_ifft_f64() {
    can_fft_impl::<f64>("can_rountrip_ifft_f64", 1e-10, Direction::Inverse);
}

#[test]
fn can_ifft_f32() {
    can_fft_impl::<f32>("can_rountrip_ifft_f32", 1e-2, Direction::Inverse);
}
