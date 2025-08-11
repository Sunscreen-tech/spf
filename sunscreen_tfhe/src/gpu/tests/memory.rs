use rand::{RngCore, rng};
use sunscreen_gpu_runtime::launch_kernel;

use crate::gpu::{Scratch, test_utils::get_runtimes};

#[test]
fn can_copy_to_and_from_shared_memory() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        let num_blocks = 13;

        // Must match what's in kernel.
        const N: usize = 2345;

        let mut input = r.allocate::<u32>(num_blocks * N).unwrap();
        let output = r.allocate::<u32>(num_blocks * N).unwrap();

        input
            .as_mut_slice()
            .iter_mut()
            .for_each(|x| *x = rng().next_u32());

        let stream = r.make_stream(0.into()).unwrap();
        let block_size = 128u32;
        let threads = num_blocks as u32 * block_size;

        unsafe {
            launch_kernel!(
                ((threads, block_size))
                ("can_copy_to_and_from_shared_memory")
                (r, stream)
                input,
                output
            )
        }
        .unwrap();

        stream.wait().unwrap();

        assert_eq!(input.as_slice(), output.as_slice());
    }
}

#[test]
fn can_use_scratch() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        let num_blocks = 13;

        // Must match what's in kernel.
        const N: usize = 2345;

        let mut a = r.allocate::<u32>(num_blocks * N).unwrap();
        let mut b = r.allocate::<u32>(num_blocks * N).unwrap();
        let output = r.allocate::<u32>(num_blocks * N).unwrap();

        a.as_mut_slice()
            .iter_mut()
            .for_each(|x| *x = rng().next_u32());
        b.as_mut_slice()
            .iter_mut()
            .for_each(|x| *x = rng().next_u32());

        let stream = r.make_stream(0.into()).unwrap();
        let block_size = 128u32;
        let threads = num_blocks as u32 * block_size;
        let grid = (threads, block_size);

        let scratch = Scratch::new(r, grid).unwrap();

        unsafe {
            launch_kernel!(
                (grid)
                ("can_use_scratch")
                (r, stream)
                a,
                b,
                output,
                scratch
            )
        }
        .unwrap();

        stream.wait().unwrap();

        for ((a, b), c) in a
            .as_slice()
            .iter()
            .zip(b.as_slice().iter())
            .zip(output.as_slice().iter())
        {
            assert_eq!(a.wrapping_add(*b), *c);
        }
    }
}
