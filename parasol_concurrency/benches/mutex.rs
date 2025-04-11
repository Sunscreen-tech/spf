use criterion::{Criterion, criterion_group, criterion_main};
use parasol_concurrency::Spinlock;

use std::sync::Mutex;

fn std_mutex_alloc(c: &mut Criterion) {
    c.bench_function("mutex allocate", |b| {
        b.iter(|| {
            let x = Mutex::new(7u32);

            let _x = x.lock().unwrap();
        });
    });
}

fn spinlock_alloc(c: &mut Criterion) {
    c.bench_function("spinlock allocate", |b| {
        b.iter(|| {
            let x = Spinlock::new(7u32);

            let _x = x.lock();
        })
    });
}

criterion_group!(benches, std_mutex_alloc, spinlock_alloc);
criterion_main!(benches);
