use sunscreen_gpu_runtime::launch_kernel;

use crate::gpu::{
    Scratch,
    test_utils::{SUPPORTED_POLY_DEGREES, get_runtimes},
};

#[test]
fn can_roundtrip_polynomial() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for d in SUPPORTED_POLY_DEGREES {
            let mut x = r.allocate::<u64>(*d as usize).unwrap();
            let y = r.allocate::<u64>(*d as usize).unwrap();

            x.as_mut_slice().iter_mut().enumerate().for_each(|(i, x)| {
                *x = i as u64;
            });

            let stream = r.make_stream().unwrap();

            let threads_per_block = d / 8;
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

            for (e, a) in x.as_slice().iter().zip(y.as_slice().iter()) {
                assert_eq!(*a, *e);
            }
        }
    }
}
