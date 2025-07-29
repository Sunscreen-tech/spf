use num::{Complex, Zero};
use sunscreen_gpu_runtime::launch_kernel;

use crate::{
    FrequencyTransform,
    fft::negacyclic,
    gpu::{test_utils::get_runtimes, tests::assert_complex_equalish},
};

#[test]
fn can_negacyclic_forward() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for n in [2048u32, 4096] {
            let num_ffts = 9;
            let num_points = num_ffts as usize * n as usize;

            let baseline_fft = negacyclic::get_fft(n.ilog2() as usize);

            let mut input = r.allocate::<f64>(num_points).unwrap();
            input.copy_from_slice(&(0..num_points).map(|x| x as f64).collect::<Vec<_>>());

            let output = r.allocate::<Complex<f64>>(num_points / 2).unwrap();

            let stream = r.make_stream().unwrap();

            let threads_per_block = n / 8;
            let num_threads = num_ffts as u32 * threads_per_block;

            unsafe {
                launch_kernel!(
                    ((num_threads, threads_per_block))
                    ("can_forward_twisted_fft_f64")
                    (r, stream, 0)
                    input,
                    output,
                    n
                )
            }
            .unwrap();

            stream.wait().unwrap();

            for (input, actual) in input
                .as_slice()
                .chunks(n as usize)
                .zip(output.as_slice().chunks((n / 2) as usize))
            {
                let mut expected = vec![Complex::<f64>::zero(); n as usize];

                baseline_fft.forward(input, &mut expected);

                for (i, (actual, expected)) in actual.iter().zip(expected.iter()).enumerate() {
                    assert_complex_equalish(actual, expected, 1e-9);
                }
            }
        }
    }
}
