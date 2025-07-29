#[cfg(all(feature = "gpu", feature = "test_kernels"))]
use criterion::{criterion_group, criterion_main};

#[cfg(all(feature = "gpu", feature = "test_kernels"))]
mod gpu_benches {
    use std::{cell::RefCell, collections::HashSet};

    use criterion::Criterion;
    use num::Complex;
    use sunscreen_gpu_runtime::{GpuRuntime, launch_kernel};
    use sunscreen_tfhe::gpu::test_utils::get_runtimes;

    pub fn for_each_device_type<F: Fn(&str, &GpuRuntime)>(f: F) {
        let mut used_devices = HashSet::new();

        let runtimes = get_runtimes();

        for r in runtimes.iter() {
            for device_id in 0..r.num_devices().unwrap() {
                let device_name = r.get_device_name(device_id.into()).unwrap();

                if !used_devices.contains(&device_name) {
                    f(&device_name, r);
                    used_devices.insert(device_name);
                }
            }
        }
    }

    pub fn fft(c: &mut Criterion) {
        let g = RefCell::new(c.benchmark_group("FFT"));

        for_each_device_type(|dev_name, r: &GpuRuntime| {
            for n in [1024, 2048] {
                let bench_name = format!("Complex<f64> FFT latency N={n} Device={dev_name} ");
                let stream = r.make_stream().unwrap();
                let num_ffts_sequence = 2 * 2 * 637u32;

                g.borrow_mut()
                    .throughput(criterion::Throughput::Elements(num_ffts_sequence as u64));
                g.borrow_mut().bench_function(&bench_name, |b| {
                    let mut buffer = r.allocate::<Complex<f64>>(n).unwrap();
                    buffer.copy_from_slice(
                        &(0..n)
                            .map(|x| Complex::new(x as f64, x as f64))
                            .collect::<Vec<_>>(),
                    );

                    let output = r.allocate::<Complex<f64>>(n).unwrap();

                    let num_ffts_sequence = 2 * 2 * 637u32;

                    b.iter(|| {
                        let num_threads = n as u32 / 4;

                        unsafe {
                            launch_kernel!(
                                ((num_threads, num_threads))
                                ("benchmark_fft_f64")
                                (r, stream, 0)
                                buffer,
                                output,
                                n as u32,
                                num_ffts_sequence
                            )
                            .unwrap();

                            stream.wait().unwrap();
                        }
                    });
                });

                let bench_name = format!("Complex<f32> FFT latency N={n} Device={dev_name} ");

                g.borrow_mut()
                    .throughput(criterion::Throughput::Elements(num_ffts_sequence as u64));
                g.borrow_mut().bench_function(&bench_name, |b| {
                    let mut buffer = r.allocate::<Complex<f32>>(n).unwrap();
                    buffer.copy_from_slice(
                        &(0..n)
                            .map(|x| Complex::new(x as f32, x as f32))
                            .collect::<Vec<_>>(),
                    );

                    let output = r.allocate::<Complex<f32>>(n).unwrap();

                    b.iter(|| {
                        let num_threads = n as u32 / 4;

                        unsafe {
                            launch_kernel!(
                                ((num_threads, num_threads))
                                ("benchmark_fft_f32")
                                (r, stream, 0)
                                buffer,
                                output,
                                n as u32,
                                num_ffts_sequence
                            )
                            .unwrap();

                            stream.wait().unwrap();
                        }
                    });
                });
            }
        });
    }
}

#[cfg(all(feature = "gpu", feature = "test_kernels"))]
use gpu_benches::*;
#[cfg(all(feature = "gpu", feature = "test_kernels"))]
criterion_group!(benches, fft);
#[cfg(all(feature = "gpu", feature = "test_kernels"))]
criterion_main!(benches);

#[cfg(not(all(feature = "gpu", feature = "test_kernels")))]
fn main() {
    println!("To run GPU benchmarks, run `cargo bench --bench gpu --features cuda,test_kernels`")
}
