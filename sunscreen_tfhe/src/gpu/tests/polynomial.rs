use aligned_vec::avec_rt;
use num::{Complex, Zero};
use rand::{RngCore, rng};
use sunscreen_gpu_runtime::launch_kernel;

use crate::{
    Torus,
    dst::{AsSlice, FromMutSlice, FromSlice},
    entities::{DstArray, Polynomial, PolynomialFftRef, PolynomialRef},
    gpu::{
        Scratch, get_runtimes,
        test_utils::SUPPORTED_POLY_DEGREES,
        tests::test_utils::{random_poly_mod, random_poly_mod_2_pow_64},
    },
    polynomial::{polynomial_add, polynomial_sub},
};

fn polynomial_roundtrip_test(kernel: &str) {
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let mut x = DstArray::<Polynomial<u64>>::new(num_blocks, d);
            let y = x.clone();

            random_poly_mod(&mut x, &d, 0x1 << 32);

            let stream = r.make_stream(0.into()).unwrap();

            let threads_per_block = d.threads_per_block();
            let num_threads = threads_per_block;

            let grid = (num_threads, threads_per_block);
            let scratch = Scratch::new(r, grid).unwrap();

            unsafe {
                launch_kernel!(
                    (grid)
                    (kernel)
                    (r, stream)
                    x,
                    y,
                    scratch,
                    d.0 as u32
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for (a, e) in x.iter(d).zip(y.iter(d)) {
                assert_eq!(a.coeffs(), e.coeffs());
            }
        }
    }
}

#[test]
fn can_roundtrip_polynomial() {
    polynomial_roundtrip_test("can_polynomial_rountrip_fft");
}

#[test]
fn can_roundtrip_polynomial_inplace() {
    polynomial_roundtrip_test("can_polynomial_rountrip_fft_inplace");
}

fn poly_op_test<F>(baseline_op: F, kernel_name: &str)
where
    F: Fn(&mut PolynomialRef<u64>, &PolynomialRef<u64>, &PolynomialRef<u64>),
{
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let c = DstArray::<Polynomial<u64>>::new(num_blocks, d);
            let mut a = c.clone();
            let mut b = c.clone();

            random_poly_mod_2_pow_64(&mut a, &d);
            random_poly_mod_2_pow_64(&mut b, &d);

            let stream = r.make_stream(0usize.into()).unwrap();
            let threads_per_block = d.threads_per_block();
            let num_threads = num_blocks as u32 * threads_per_block;

            unsafe {
                launch_kernel!(
                    ((num_threads, threads_per_block))
                    (kernel_name)
                    (r, stream)
                    c,
                    a,
                    b,
                    d.0 as u32
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for ((c, a), b) in c.iter(d).zip(a.iter(d)).zip(b.iter(d)) {
                let mut expected = Polynomial::<u64>::zero(d.0);

                baseline_op(&mut expected, a, b);

                assert_eq!(c.as_slice(), expected.as_slice());
            }
        }
    }
}

#[test]
fn can_sub_polynomials() {
    poly_op_test(|c, a, b| polynomial_sub(c, a, b), "can_sub_polynomials");
}

#[test]
fn can_add_polynomials() {
    poly_op_test(|c, a, b| polynomial_add(c, a, b), "can_add_polynomials");
}

/*
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
 */
