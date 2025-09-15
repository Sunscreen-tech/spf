use aligned_vec::avec;
use criterion::{Criterion, criterion_group, criterion_main};
use num::{Complex};
use rustfft::{FftDirection, FftPlanner as RustfftFft};
use spqlios_sys::Fft as SpqliosFft;
use sunscreen_tfhe::{FrequencyTransform, math::fft::negacyclic::TwistedFft};

fn negacyclic_fft(c: &mut Criterion) {
    let n = 2048;

    let plan = TwistedFft::<f64>::new(n);

    let x = (0..n).map(|x| x as f64).collect::<Vec<_>>();
    let mut y = vec![Complex::from(0.0); x.len() / 2];

    c.bench_function("FFT 2048", |s| {
        s.iter(|| {
            plan.forward(&x, &mut y);
        });
    });

    let n = 1024;

    let plan = TwistedFft::<f64>::new(n);

    let x = (0..n).map(|x| x as f64).collect::<Vec<_>>();
    let mut y = vec![Complex::from(0.0); x.len() / 2];

    c.bench_function("FFT 1024", |s| {
        s.iter(|| {
            plan.forward(&x, &mut y);
        });
    });

    let n: usize = 256;

    let plan = TwistedFft::<f64>::new(n);

    let x = (0..n).map(|x| x as f64).collect::<Vec<_>>();
    let mut y = vec![Complex::from(0.0); x.len() / 2];

    c.bench_function("FFT 256", |s| {
        s.iter(|| {
            plan.forward(&x, &mut y);
        });
    });
}

fn raw_fft(c: &mut Criterion) {
    c.bench_function("spqlios raw FFT", |b| {
        let mut x = avec![[64]| 0f64; 2048];
        let fft = SpqliosFft::new(1024);

        b.iter(|| {
            fft.fft_inplace(&mut x);
        });
    });

    c.bench_function("spqlios raw IFFT", |b| {
        let mut x = avec![[64]| 0f64; 2048];
        let fft = SpqliosFft::new(1024);

        b.iter(|| {
            fft.ifft_inplace(&mut x);
        });
    });

    c.bench_function("rustfft raw FFT", |b| {
        let mut x = avec![[64]| Complex::<f64>::ZERO; 1024];
        let mut planner = RustfftFft::new();
        let fft = planner.plan_fft(1024, FftDirection::Forward);

        b.iter(|| {
            fft.process(&mut x);
        });
    });

    c.bench_function("rustfft raw IFFT", |b| {
        let mut x = avec![[64]| Complex::<f64>::ZERO; 1024];
        let mut planner = RustfftFft::new();
        let ifft = planner.plan_fft(1024, FftDirection::Inverse);

        b.iter(|| {
            ifft.process(&mut x);
        });
    });
}

criterion_group!(benches, negacyclic_fft, raw_fft);
criterion_main!(benches);
