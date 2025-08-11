use aligned_vec::avec_rt;
use num::{Complex, Zero};
use rand::{RngCore, rng};
use sunscreen_gpu_runtime::launch_kernel;

use crate::{
    Torus,
    dst::{AsSlice, FromMutSlice, FromSlice},
    entities::{Polynomial, PolynomialFftRef, PolynomialRef},
    gpu::{
        Scratch,
        test_utils::{PolyDegreeInfo, SUPPORTED_POLY_DEGREES, get_runtimes},
    },
    polynomial::{polynomial_add, polynomial_sub},
};

#[test]
fn can_roundtrip_polynomial() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let mut x = r.allocate::<u64>(*d as usize).unwrap();
            let y = r.allocate::<u64>(*d as usize).unwrap();

            x.as_mut_slice().iter_mut().enumerate().for_each(|(i, x)| {
                *x = i as u64;
            });

            let stream = r.make_stream(0.into()).unwrap();

            let threads_per_block = d.threads_per_block();
            let num_threads = threads_per_block;

            let grid = (num_threads, threads_per_block);
            let scratch = Scratch::new(r, grid).unwrap();

            unsafe {
                launch_kernel!(
                    (grid)
                    ("can_polynomial_rountrip_fft")
                    (r, stream)
                    x,
                    y,
                    scratch,
                    *d as u32
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for (e, a) in x.as_slice().iter().zip(y.as_slice().iter()) {
                assert_eq!(*a, *e);
            }
        }
    }
}

#[test]
fn can_roundtrip_polynomial_inplace() {
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let len = (*d * num_blocks) as usize;

            let mut x = r.allocate::<u64>(len).unwrap();
            let y = r.allocate::<u64>(len).unwrap();

            x.as_mut_slice().iter_mut().enumerate().for_each(|(i, x)| {
                *x = i as u64;
            });

            let stream = r.make_stream(0.into()).unwrap();

            let threads_per_block = d.threads_per_block();
            let num_threads = threads_per_block * num_blocks;

            let grid = (num_threads, threads_per_block);

            unsafe {
                launch_kernel!(
                    (grid)
                    ("can_polynomial_rountrip_fft_inplace")
                    (r, stream)
                    x,
                    y,
                    *d as u32
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for (e, a) in x.as_slice().iter().zip(y.as_slice().iter()) {
                assert_eq!(*a, *e);
            }
        }
    }
}

fn poly_op_test<T, F>(baseline_op: F, kernel_name: &str)
where
    F: Fn(&mut PolynomialRef<T>, &PolynomialRef<T>, &PolynomialRef<T>),
    T: Clone + num::Zero + bytemuck::Pod + std::fmt::Debug + PartialEq,
    u64: Into<T>,
{
    let runtimes = get_runtimes();
    let num_blocks = 13u32;

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let len = (num_blocks * *d) as usize;
            let c = r.allocate::<T>(len).unwrap();
            let mut a = r.allocate::<T>(len).unwrap();
            let mut b = r.allocate::<T>(len).unwrap();

            a.as_mut_slice()
                .iter_mut()
                .for_each(|x| *x = rng().next_u64().into());
            b.as_mut_slice()
                .iter_mut()
                .for_each(|x| *x = rng().next_u64().into());

            let stream = r.make_stream(0usize.into()).unwrap();
            let threads_per_block = d.threads_per_block();

            unsafe {
                launch_kernel!(
                    ((num_blocks * threads_per_block, threads_per_block))
                    (kernel_name)
                    (r, stream)
                    c,
                    a,
                    b,
                    *d
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for ((c, a), b) in c
                .as_slice()
                .chunks(*d as usize)
                .zip(a.as_slice().chunks(*d as usize))
                .zip(b.as_slice().chunks(*d as usize))
            {
                let a = Polynomial::new(a);
                let b = Polynomial::new(b);
                let c = Polynomial::new(c);
                let mut expected = Polynomial::zero(*d as usize);

                baseline_op(&mut expected, &a, &b);

                assert_eq!(c.as_slice(), expected.as_slice());
            }
        }
    }
}

#[test]
fn can_sub_polynomials() {
    poly_op_test::<Torus<u64>, _>(|c, a, b| polynomial_sub(c, a, b), "can_sub_polynomials");
}

#[test]
fn can_add_polynomials() {
    poly_op_test::<Torus<u64>, _>(|c, a, b| polynomial_add(c, a, b), "can_add_polynomials");
}

#[test]
fn can_mad_polynomials() {
    let runtimes = get_runtimes();
    let num_blocks = 13u32;

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let d = PolyDegreeInfo(*d / 2);

            let len = (num_blocks * *d / 2) as usize;
            let mut c = r.allocate::<Complex<f64>>(len).unwrap();
            let mut a = r.allocate::<Complex<f64>>(len).unwrap();
            let mut b = r.allocate::<Complex<f64>>(len).unwrap();

            a.as_mut_slice()
                .iter_mut()
                .for_each(|x| *x = Complex::new(rng().next_u64() as f64, rng().next_u64() as f64));
            b.as_mut_slice()
                .iter_mut()
                .for_each(|x| *x = Complex::new(rng().next_u64() as f64, rng().next_u64() as f64));
            c.as_mut_slice()
                .iter_mut()
                .for_each(|x| *x = Complex::new(rng().next_u64() as f64, rng().next_u64() as f64));

            let mut expected = avec_rt!([64]| Complex::<f64>::zero(); len);
            expected.as_mut_slice().clone_from_slice(c.as_slice());

            let stream = r.make_stream(0.into()).unwrap();
            let threads_per_block = d.threads_per_block();

            unsafe {
                launch_kernel!(
                    ((num_blocks * threads_per_block, threads_per_block))
                    ("can_mad_polynomials")
                    (r, stream)
                    c,
                    a,
                    b,
                    *d
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for (((c, a), b), e) in c
                .as_slice()
                .chunks(*d as usize)
                .zip(a.as_slice().chunks(*d as usize))
                .zip(b.as_slice().chunks(*d as usize))
                .zip(expected.chunks_mut(*d as usize))
            {
                let a = PolynomialFftRef::from_slice(a);
                let b = PolynomialFftRef::from_slice(b);
                let c = PolynomialFftRef::from_slice(c);

                let expected = PolynomialFftRef::from_mut_slice(e);

                expected.multiply_add(&a, &b);

                for (a, e) in c.as_slice().iter().zip(expected.as_slice().iter()) {
                    approx::assert_relative_eq!(a.re, e.re, max_relative = 1e-11);
                    approx::assert_relative_eq!(a.im, e.im, max_relative = 1e-11);
                }
            }
        }
    }
}
