#[cfg(all(feature = "gpu", feature = "test_kernels"))]
use criterion::{criterion_group, criterion_main};

#[cfg(all(feature = "gpu", feature = "test_kernels"))]
mod gpu_benches {
    use std::{cell::RefCell, collections::HashSet, sync::Arc};

    use criterion::Criterion;
    use num::Complex;
    use sunscreen_gpu_runtime::{GpuRuntime, launch_kernel};
    use sunscreen_tfhe::{
        entities::{BootstrapKeyFft, BootstrapKeyFftRef, DstArray, GlweCiphertext, GlweCiphertextRef, GlweSecretKey, LweCiphertext, LweSecretKey, UnivariateLookupTable}, gpu::{get_runtimes, ops::{bootstrapping::gpu_generalized_functional_bootstrap, keys::gpu_fft_bootstrap_key}, Scratch}, high_level, OverlaySize, PlaintextBits, RadixCount, RadixDecomposition, RadixLog, Torus, GLWE_1_2048_128, LWE_637_128
    };

    pub fn for_each_device_type<F: Fn(&str, &Arc<GpuRuntime>)>(f: F) {
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
        let shared_memory = 48 * 1024;

        let g = RefCell::new(c.benchmark_group("FFT"));

        for_each_device_type(|dev_name, r| {
            for n in [1024] {
                let bench_name =
                    format!("Complex<f64> FFT latency N={n} Device={dev_name} noreorder");
                let stream = r.make_stream(0.into()).unwrap();
                let ffts_in_parallel = 2;
                let num_ffts_sequence = 2 * 2 * 637u32 / ffts_in_parallel;

                g.borrow_mut().throughput(criterion::Throughput::Elements(
                    (ffts_in_parallel * num_ffts_sequence) as u64,
                ));
                g.borrow_mut().bench_function(&bench_name, |b| {
                    let mut buffer = GpuRuntime::allocate::<Complex<f64>>(r, n).unwrap();
                    buffer.copy_from_slice(
                        &(0..n)
                            .map(|x| Complex::new(x as f64, x as f64))
                            .collect::<Vec<_>>(),
                    );

                    let output = GpuRuntime::allocate::<Complex<f64>>(r, n).unwrap();

                    b.iter(|| {
                        let num_threads = n as u32 / 4;

                        unsafe {
                            launch_kernel!(
                                (((num_threads, num_threads), (ffts_in_parallel, ffts_in_parallel)))
                                ("benchmark_fft_f64")
                                (r, stream, shared_memory)
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

                let bench_name =
                    format!("Complex<f32> FFT latency N={n} Device={dev_name} noreorder");

                g.borrow_mut().throughput(criterion::Throughput::Elements(
                    (ffts_in_parallel * num_ffts_sequence) as u64,
                ));
                g.borrow_mut().bench_function(&bench_name, |b| {
                    let mut buffer = GpuRuntime::allocate::<Complex<f32>>(r, n).unwrap();
                    buffer.copy_from_slice(
                        &(0..n)
                            .map(|x| Complex::new(x as f32, x as f32))
                            .collect::<Vec<_>>(),
                    );

                    let output = GpuRuntime::allocate::<Complex<f32>>(r, n).unwrap();

                    b.iter(|| {
                        let num_threads = n as u32 / 4;

                        unsafe {
                            launch_kernel!(
                                (((num_threads, num_threads), (ffts_in_parallel, ffts_in_parallel)))
                                ("benchmark_fft_f32")
                                (r, stream, shared_memory)
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

    pub fn serial_pbs(c: &mut Criterion) {
        let g = RefCell::new(c.benchmark_group("serial PBS"));

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
                
                let mut bsk_fft = BootstrapKeyFft::new(&lwe, &glwe, &pbs_radix);

                let mut results = DstArray::<GlweCiphertext<u64>>::new(pbs_count, glwe.dim);
                let inputs = DstArray::<LweCiphertext<u64>>::new(pbs_count, lwe.dim);

                let stream = r.make_stream(0.into()).unwrap();
                let bsk = gpu_fft_bootstrap_key(&mut bsk_fft, &bsk, &lwe, &glwe, &pbs_radix, r, &stream).unwrap();
                let lut = UnivariateLookupTable::trivial_from_fn(|_| {1}, &glwe, PlaintextBits(1));

                g.borrow_mut().bench_function(
                    &format!("serial PBS {dev_name} count={pbs_count}"),
                    |b| {
                        b.iter(|| {
                            gpu_generalized_functional_bootstrap(
                                &mut results,
                                &inputs,
                                &lut,
                                &bsk_fft,
                                0,
                                3,
                                &lwe,
                                &glwe,
                                &pbs_radix,
                                &r,
                                &stream
                            ).unwrap();

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
criterion_group!(benches, fft, serial_pbs);
#[cfg(all(feature = "gpu", feature = "test_kernels"))]
criterion_main!(benches);

#[cfg(not(all(feature = "gpu", feature = "test_kernels")))]
fn main() {
    println!("To run GPU benchmarks, run `cargo bench --bench gpu --features cuda,test_kernels`")
}
