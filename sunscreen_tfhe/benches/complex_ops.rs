use aligned_vec::avec;
use criterion::{Criterion, criterion_group, criterion_main};
use num::Complex;

fn complex_mad(c: &mut Criterion) {
    c.bench_function("Complex f64 c+=a*b", |bench| {
        let mut c = avec![[64]| Complex::<f64>::ZERO; 1024];
        let a = avec![[64]| Complex::<f64>::ZERO; 1024];
        let b = avec![[64]| Complex::<f64>::ZERO; 1024];

        bench.iter(|| {
            sunscreen_tfhe::math::simd::complex_mad(&mut c, &a, &b);
        });
    });
}

fn realimag_mad(c: &mut Criterion) {
    c.bench_function("realimag f64 c+=a*b", |bench| {
        let mut c = avec![[64]| 0.0f64; 2048];
        let a = avec![[64]| 0.0f64; 2048];
        let b = avec![[64]| 0.0f64; 2048];

        bench.iter(|| {
            sunscreen_tfhe::math::simd::realimag_mad(&mut c, &a, &b);
        });
    });
}

criterion_group!(benches, complex_mad, realimag_mad);
criterion_main!(benches);
