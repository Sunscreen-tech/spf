use num::Complex;

use crate::gpu::tests::get_runtimes;

#[allow(unused)]
trait CastComplexF64Slice {
    fn cast_slice_complex_f64(&self) -> &[Complex<f64>];
}

trait CastComplexF64SliceMut {
    fn cast_slice_complex_f64_mut(&mut self) -> &mut [Complex<f64>];
}

impl CastComplexF64Slice for &[u8] {
    fn cast_slice_complex_f64(&self) -> &[Complex<f64>] {
        let clen = std::mem::size_of::<Complex<f64>>();

        assert!(self.len() % clen != 0);

        unsafe {
            std::slice::from_raw_parts(self.as_ptr() as *const Complex<f64>, self.len() / clen)
        }
    }
}

impl CastComplexF64SliceMut for &mut [u8] {
    fn cast_slice_complex_f64_mut(&mut self) -> &mut [Complex<f64>] {
        let clen = std::mem::size_of::<Complex<f64>>();

        assert!(self.len() % clen == 0);

        dbg!((self.len(), clen));

        unsafe {
            std::slice::from_raw_parts_mut(
                self.as_mut_ptr() as *mut Complex<f64>,
                self.len() / clen,
            )
        }
    }
}

#[test]
fn can_roundtrip_fft() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        for n in [512u32, 1024, 2048, 4096] {
            let csize = std::mem::size_of::<Complex<f64>>();

            let a_gpu = r.allocate(n as usize * csize).unwrap();

            let _result_gpu = r.allocate(n as usize * csize).unwrap();

            let mut gpu_data = unsafe { a_gpu.as_mut_slice() };
            let gpu_data = gpu_data.cast_slice_complex_f64_mut();

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
