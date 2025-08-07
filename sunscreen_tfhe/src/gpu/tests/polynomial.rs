use rand::{RngCore, thread_rng};
use sunscreen_gpu_runtime::launch_kernel;

use crate::{
    dst::AsSlice, entities::{Polynomial, PolynomialRef}, gpu::{
        test_utils::{get_runtimes, SUPPORTED_POLY_DEGREES}, Scratch
    }, polynomial::{polynomial_add, polynomial_sub}, Torus
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

            let stream = r.make_stream().unwrap();

            let threads_per_block = d.threads_per_block();
            let num_threads = threads_per_block;

            let grid = (num_threads, threads_per_block);
            let scratch = Scratch::new(r, grid).unwrap();

            unsafe {
                launch_kernel!(
                    (grid)
                    ("can_polynomial_rountrip_fft")
                    (r, stream, 0)
                    x,
                    y,
                    scratch,
                    *d
                )
            }
            .unwrap();

            stream.wait().unwrap();

            dbg!(x.as_slice());
            dbg!(y.as_slice());

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
    u64: Into<T>
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
                .for_each(|x| *x = thread_rng().next_u64().into());
            b.as_mut_slice()
                .iter_mut()
                .for_each(|x| *x = thread_rng().next_u64().into());

            let stream = r.make_stream().unwrap();
            let threads_per_block = d.threads_per_block();

            unsafe {
                launch_kernel!(
                    ((num_blocks * threads_per_block, threads_per_block))
                    (kernel_name)
                    (r, stream, 0usize)
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
