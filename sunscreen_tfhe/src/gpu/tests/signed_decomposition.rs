use rand::{RngCore, thread_rng};
use sunscreen_gpu_runtime::launch_kernel;

use crate::{
    RadixCount, RadixDecomposition, RadixLog, Torus,
    dst::{AsSlice, FromSlice},
    entities::{Polynomial, PolynomialRef},
    gpu::test_utils::{SUPPORTED_POLY_DEGREES, get_runtimes},
    radix::PolynomialRadixIterator,
};

#[test]
fn can_signed_decompose_polynomial() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let num_blocks = 13;
            let len = (num_blocks * *d) as usize;

            let mut poly = r.allocate::<Torus<u64>>(len).unwrap();
            let scratch = r.allocate::<Torus<u64>>(len).unwrap();
            let o1 = r.allocate::<u64>(len).unwrap();
            let o2 = r.allocate::<u64>(len).unwrap();
            let o3 = r.allocate::<u64>(len).unwrap();
            let o4 = r.allocate::<u64>(len).unwrap();

            let radix = RadixDecomposition {
                count: RadixCount(4),
                radix_log: RadixLog(3),
            };

            poly.as_mut_slice()
                .iter_mut()
                .for_each(|x| *x = Torus::from(thread_rng().next_u64()));

            let stream = r.make_stream().unwrap();

            let threads_per_block = d.threads_per_block();
            let num_threads = num_blocks * threads_per_block;
            unsafe {
                launch_kernel!(
                    ((num_threads, threads_per_block))
                    ("can_decompose_polynomial")
                    (r, stream, 0)
                    poly,
                    scratch,
                    o1,
                    o2,
                    o3,
                    o4
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for ((((poly, o1), o2), o3), o4) in poly
                .as_slice()
                .chunks(*d as usize)
                .zip(o1.as_slice().chunks(*d as usize))
                .zip(o2.as_slice().chunks(*d as usize))
                .zip(o3.as_slice().chunks(*d as usize))
                .zip(o4.as_slice().chunks(*d as usize))
            {
                let poly = PolynomialRef::from_slice(poly);
                let o1 = PolynomialRef::from_slice(o1);
                let o2 = PolynomialRef::from_slice(o2);
                let o3 = PolynomialRef::from_slice(o3);
                let o4 = PolynomialRef::from_slice(o4);

                let mut scratch = Polynomial::zero(*d as usize);
                let mut actual = Polynomial::zero(*d as usize);

                let mut baseline = PolynomialRadixIterator::new(poly, &mut scratch, &radix);

                baseline.write_next(&mut actual);
                assert_eq!(actual.as_slice(), o1.as_slice());
                baseline.write_next(&mut actual);
                assert_eq!(actual.as_slice(), o2.as_slice());
                baseline.write_next(&mut actual);
                assert_eq!(actual.as_slice(), o3.as_slice());
                baseline.write_next(&mut actual);
                assert_eq!(actual.as_slice(), o4.as_slice());
            }
        }
    }
}
