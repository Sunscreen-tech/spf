use criterion::{criterion_group, criterion_main, Criterion};
use num::Complex;

fn complex_mad(c: &mut Criterion) {
    c.bench_function("Complex f64 c+=a*b", |bench| {
        let mut c = vec![Complex::<f64>::ZERO; 1024];
        let a = vec![Complex::<f64>::ZERO; 1024];
        let b = vec![Complex::<f64>::ZERO; 1024];

        bench.iter(|| {
            sunscreen_tfhe::math::simd::complex_mad(&mut c, &a, &b);
        });
    });
}

fn realimag_mad(c: &mut Criterion) {
    c.bench_function("realimag f64 c+=a*b", |bench| {
        let mut c = vec![0.0f64; 2048];
        let a = vec![0.0f64; 2048];
        let b = vec![0.0f64; 2048];

        bench.iter(|| {
            sunscreen_tfhe::math::simd::realimag_mad(&mut c, &a, &b);
        });
    });
}

criterion_group!(benches, complex_mad, realimag_mad);
criterion_main!(benches);
