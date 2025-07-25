use num::Complex;

use crate::gpu::tests::get_runtimes;

#[test]
fn can_roundtrip_fft() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for n in [512u32, 1024, 2048, 4096] {
            let mut a_gpu = r.allocate::<Complex<f64>>(n as usize).unwrap();

            let _result_gpu = r.allocate::<Complex<f64>>(n as usize).unwrap();

            let gpu_data = unsafe { a_gpu.as_mut_slice() };

            gpu_data.copy_from_slice(
                &(0..n)
                    .map(|x| Complex::new(x as f64, (n - x) as f64))
                    .collect::<Vec<_>>(),
            );

            let _stream = r.make_stream().unwrap();

            // WIP
        }
    }
}
