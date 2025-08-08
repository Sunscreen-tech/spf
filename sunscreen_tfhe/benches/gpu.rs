#[cfg(all(feature = "gpu", feature = "test_kernels"))]
use criterion::{criterion_group, criterion_main};

#[cfg(all(feature = "gpu", feature = "test_kernels"))]
mod gpu_benches {
    use std::{cell::RefCell, collections::HashSet};

    use criterion::Criterion;
    use num::Complex;
    use sunscreen_gpu_runtime::{GpuRuntime, launch_kernel};
    use sunscreen_tfhe::{
        GLWE_1_1024_128, GLWE_1_2048_128, LWE_637_128, OverlaySize, RadixCount, RadixDecomposition,
        RadixLog, Torus,
        entities::{
            BootstrapKey, BootstrapKeyFftRef, GlweCiphertextRef, GlweSecretKey, LweSecretKey,
        },
        gpu::{Scratch, test_utils::get_runtimes},
        high_level,
    };

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
            for reorder in [false, true] {
                for n in [1024] {
                    let bench_name = format!(
                        "Complex<f64> FFT latency N={n} Device={dev_name} reorder={reorder}"
                    );
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
                                    num_ffts_sequence,
                                    reorder as u32
                                )
                                .unwrap();

                                stream.wait().unwrap();
                            }
                        });
                    });

                    let bench_name = format!(
                        "Complex<f32> FFT latency N={n} Device={dev_name} reorder={reorder}"
                    );

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
                                    num_ffts_sequence,
                                    reorder as u32
                                )
                                .unwrap();

                                stream.wait().unwrap();
                            }
                        });
                    });
                }
            }
        });
    }

    pub fn synthetic_pbs(c: &mut Criterion) {
        let mut g = RefCell::new(c.benchmark_group("Synthetic PBS"));

        for_each_device_type(|dev_name, r| {
            for log_count in 0..12 {
                let pbs_count = 0x1 << log_count;

                let pbs_radix = RadixDecomposition {
                    count: RadixCount(2),
                    radix_log: RadixLog(16),
                };

                let lwe = LWE_637_128;
                let glwe = GLWE_1_2048_128;

                let lwe_sk = LweSecretKey::generate_binary(&lwe);
                let glwe_sk = GlweSecretKey::generate_binary(&glwe);
                let bsk = high_level::keygen::generate_bootstrapping_key(
                    &lwe_sk, &glwe_sk, &lwe, &glwe, &pbs_radix,
                );
                let bsk = high_level::fft::fft_bootstrap_key(&bsk, &lwe, &glwe, &pbs_radix);

                g.borrow_mut().bench_function(
                    &format!("Synthetic PBS {dev_name} count={pbs_count}"),
                    |b| {
                        let res = r
                            .allocate::<Torus<u64>>(
                                pbs_count * GlweCiphertextRef::<u64>::size(glwe.dim),
                            )
                            .unwrap();
                        let mut bsk_dev = r
                            .allocate::<Complex<f64>>(BootstrapKeyFftRef::size((
                                lwe.dim,
                                glwe.dim,
                                pbs_radix.count,
                            )))
                            .unwrap();

                        let stream = r.make_stream().unwrap();
                        let tpb = glwe.dim.polynomial_degree.threads_per_block();
                        let threads = pbs_count as u32 * tpb;
                        let grid = (threads, tpb);
                        let scratch = Scratch::new(r, grid).unwrap();

                        

                        b.iter(|| {
                            unsafe {
                                launch_kernel!(
                                    (grid)
                                    ("synthetic_pbs")
                                    (r, stream, 0)
                                    res,
                                    bsk_dev,
                                    scratch
                                )
                            }
                            .unwrap();
                            stream.wait().unwrap();
                        });                       
                    },
                );
            }
        });
    }
}

#[cfg(all(feature = "gpu", feature = "test_kernels"))]
use gpu_benches::*;
#[cfg(all(feature = "gpu", feature = "test_kernels"))]
criterion_group!(benches, fft, synthetic_pbs);
#[cfg(all(feature = "gpu", feature = "test_kernels"))]
criterion_main!(benches);

#[cfg(not(all(feature = "gpu", feature = "test_kernels")))]
fn main() {
    println!("To run GPU benchmarks, run `cargo bench --bench gpu --features cuda,test_kernels`")
}
