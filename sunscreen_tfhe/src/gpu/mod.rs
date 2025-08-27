use std::io::{Cursor, Read};
use std::sync::{Arc, OnceLock};

use sunscreen_gpu_runtime::{
    Allocation, AsKernelArg, ComputeVersion, GpuRuntime, Grid, launch_kernel,
};

/// GPU-compatible FHE parameter types
pub mod gpu_params;

/// GPU-accelerated FHE operations.
pub mod ops;

#[cfg(test)]
mod tests;

use sunscreen_gpu_runtime::Result;
use zip::ZipArchive;
use zip::read::read_zipfile_from_stream;

#[doc(hidden)]
pub fn get_kernels(compute_version: ComputeVersion) -> &'static [u8] {
    #[cfg(not(any(feature = "test_kernels", test)))]
    const GPU_KERNELS_CC_70_ZIP: &[u8] = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/sunscreen_tfhe_gpu.release.compute_70.zip"
    ));

    #[cfg(not(any(feature = "test_kernels", test)))]
    const GPU_KERNELS_CC_90_ZIP: &[u8] = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/sunscreen_tfhe_gpu.release.compute_90.zip"
    ));

    #[cfg(any(feature = "test_kernels", test))]
    const GPU_KERNELS_CC_70_ZIP: &[u8] = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/sunscreen_tfhe_gpu.test.compute_70.zip"
    ));

    #[cfg(any(feature = "test_kernels", test))]
    const GPU_KERNELS_CC_90_ZIP: &[u8] = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/sunscreen_tfhe_gpu.test.compute_90.zip"
    ));

    static CUDA_70_DATA: OnceLock<Vec<u8>> = OnceLock::new();
    static CUDA_90_DATA: OnceLock<Vec<u8>> = OnceLock::new();

    let v_7 = ComputeVersion { major: 7, minor: 0 };
    let v_9 = ComputeVersion { major: 9, minor: 0 };

    fn decompress(zip_data: &[u8]) -> Vec<u8> {
        let mut cursor = Cursor::new(zip_data);

        let mut zip_file = ZipArchive::new(&mut cursor).unwrap();

        let mut contents = vec![];
        zip_file
            .by_index(0)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();

        // Append a null terminator to make the data a C string.
        contents.push(0);

        println!("{}", String::from_utf8(contents.clone()).unwrap());

        contents
    }

    if compute_version >= v_7 {
        let data = CUDA_70_DATA.get_or_init(|| decompress(GPU_KERNELS_CC_70_ZIP));

        data.as_ref()
    } else if compute_version >= v_9 {
        let data = CUDA_90_DATA.get_or_init(|| decompress(GPU_KERNELS_CC_90_ZIP));

        data.as_ref()
    } else {
        panic!("compute capability not supported: {compute_version:#?}");
    }
}

#[doc(hidden)]
pub fn get_runtimes() -> Arc<Vec<Arc<GpuRuntime>>> {
    static RUNTIMES: OnceLock<Arc<Vec<Arc<GpuRuntime>>>> = OnceLock::new();

    RUNTIMES
        .get_or_init(|| {
            sunscreen_gpu_runtime::init_runtimes(get_kernels);
            sunscreen_gpu_runtime::get_runtimes()
        })
        .clone()
}

#[cfg(any(feature = "test_kernels", test))]
#[doc(hidden)]
pub mod test_utils {
    use crate::PolynomialDegree;

    pub const SUPPORTED_POLY_DEGREES: &[PolynomialDegree] = &[PolynomialDegree(2048usize)];
}

/// Scratch space used during GPU computation.
pub struct Scratch {
    /// Allocations are in 16-byte increments.
    alloc: Allocation<[u8; 16]>,
}

impl Scratch {
    /// Allocate a new scratch buffer compatible with the given launch grid.
    pub fn new<G: Grid>(r: &Arc<GpuRuntime>, grid: G) -> Result<Self> {
        static SIZE: OnceLock<u32> = OnceLock::new();

        // Size is in 16-byte Complex<f64> values...
        let size_per_block = *SIZE.get_or_init(|| {
            let size = GpuRuntime::allocate::<u32>(r, 1).unwrap();

            let stream = r.make_stream(0.into()).unwrap();

            unsafe {
                launch_kernel!(
                    ((1, 1))
                    ("query_scratch_size_per_block")
                    (r, stream, 0)
                    size
                )
            }
            .unwrap();

            stream.wait().unwrap();

            size.as_slice()[0]
        });

        let threads = grid.x().total_threads;
        let block = grid.x().threads_per_block;

        let num_blocks = threads.next_multiple_of(block) / block;

        Ok(Self {
            alloc: GpuRuntime::allocate::<[u8; 16]>(r, (size_per_block * num_blocks) as usize)?,
        })
    }
}

impl AsKernelArg for Scratch {
    fn as_kernel_arg(&self) -> *const std::ffi::c_void {
        self.alloc.as_kernel_arg()
    }
}
