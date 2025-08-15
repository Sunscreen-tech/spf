use num::Zero;
use sunscreen_gpu_runtime::launch_kernel;

use crate::{
    dst::AsSlice, entities::{DstArray, Polynomial, PolynomialRef}, gpu::{
        get_runtimes, test_utils::SUPPORTED_POLY_DEGREES, tests::test_utils::{glwe_encrypt, random_poly_mod, random_poly_mod_2_pow_64}, Scratch
    }, high_level, polynomial::{polynomial_add, polynomial_sub}
};

fn polynomial_roundtrip_test(kernel: &str) {
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let mut x = DstArray::<Polynomial<u64>>::new(num_blocks, d);
            let y = x.clone();

            random_poly_mod(&mut x, &d, 0x1 << 48);

            let stream = r.make_stream(0.into()).unwrap();

            let threads_per_block = d.threads_per_block();
            let num_threads = num_blocks as u32 * threads_per_block;

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

#[test]
fn can_mad_polynomials() {
    let runtimes = get_runtimes();
    let num_blocks = 13;

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let mut c = DstArray::<Polynomial<u64>>::new(num_blocks, d);
            let mut a = c.clone();
            let mut b = c.clone();

            // Do something representative of a base decomposition.
            // a and c are random over the full u64, while b is over 16-bit integers
            //random_poly_mod_2_pow_64(&mut c, &d);
            //random_poly_mod_2_pow_64(&mut a, &d);
            random_poly_mod(&mut c, &d, 0x1 << 48);
            random_poly_mod(&mut a, &d, 0x1 << 48);
            random_poly_mod(&mut b, &d, 0x1 << 4);

            let c_orig = c.clone();

            let stream = r.make_stream(0.into()).unwrap();
            let threads_per_block = d.threads_per_block();
            let num_threads = num_blocks as u32 * threads_per_block;
            let grid = (num_threads, threads_per_block);

            let scratch = Scratch::new(r, grid).unwrap();

            unsafe {
                launch_kernel!(
                    (grid)
                    ("can_mad_polynomials")
                    (r, stream)
                    c,
                    a,
                    b,
                    scratch,
                    d.0 as u32
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for i in 0..num_blocks {
                let c_orig = c_orig.iter(d).nth(i).unwrap();
                let a = a.iter(d).nth(i).unwrap();
                let b = b.iter(d).nth(i).unwrap();

                let mut c_fft = high_level::fft::fft_polynomial(&c_orig, &d);
                let a_fft = high_level::fft::fft_polynomial(&a, &d);
                let b_fft = high_level::fft::fft_polynomial(&b, &d);

                let actual = c.iter(d).nth(i).unwrap();

                c_fft.multiply_add(&a_fft, &b_fft);

                let mut expected = Polynomial::<u64>::zero(d.0);
                c_fft.ifft(&mut expected);

                for (a, e) in actual.coeffs().iter().zip(expected.coeffs().iter()) {
                    assert_eq!(a, e);
                }
            }
        }
    }
}
