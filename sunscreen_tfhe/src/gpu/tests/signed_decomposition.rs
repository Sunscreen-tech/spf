use rand::{RngCore, rng};
use sunscreen_gpu_runtime::{GpuRuntime, launch_kernel};

use crate::{
    RadixCount, RadixDecomposition, RadixLog, Torus,
    dst::{AsSlice, FromSlice},
    entities::{Polynomial, PolynomialRef},
    gpu::{get_runtimes, test_utils::SUPPORTED_POLY_DEGREES, tests::get_shared_memory_bytes},
    radix::PolynomialRadixIterator,
};

#[test]
fn can_signed_decompose_polynomial() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES.iter().copied() {
            let num_blocks = 13;
            let len = num_blocks * d.0;

            let mut poly = GpuRuntime::allocate::<Torus<u64>>(r, len).unwrap();
            let scratch = GpuRuntime::allocate::<Torus<u64>>(r, len).unwrap();
            let o1 = GpuRuntime::allocate::<u64>(r, len).unwrap();
            let o2 = GpuRuntime::allocate::<u64>(r, len).unwrap();
            let o3 = GpuRuntime::allocate::<u64>(r, len).unwrap();
            let o4 = GpuRuntime::allocate::<u64>(r, len).unwrap();

            let radix = RadixDecomposition {
                count: RadixCount(4),
                radix_log: RadixLog(3),
            };

            poly.as_mut_slice()
                .iter_mut()
                .for_each(|x| *x = Torus::from(rng().next_u64()));

            let stream = r.make_stream(0.into()).unwrap();

            let threads_per_block = d.threads_per_block();
            let num_threads = num_blocks as u32 * threads_per_block;
            unsafe {
                launch_kernel!(
                    ((num_threads, threads_per_block))
                    ("can_decompose_polynomial")
                    (r, stream, get_shared_memory_bytes())
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
                .chunks(d.0)
                .zip(o1.as_slice().chunks(d.0))
                .zip(o2.as_slice().chunks(d.0))
                .zip(o3.as_slice().chunks(d.0))
                .zip(o4.as_slice().chunks(d.0))
            {
                let poly = PolynomialRef::from_slice(poly);
                let o1 = PolynomialRef::from_slice(o1);
                let o2 = PolynomialRef::from_slice(o2);
                let o3 = PolynomialRef::from_slice(o3);
                let o4 = PolynomialRef::from_slice(o4);

                let mut scratch = Polynomial::zero(d.0);
                let mut actual = Polynomial::zero(d.0);

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
