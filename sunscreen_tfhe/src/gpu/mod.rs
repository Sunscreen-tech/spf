use std::sync::{Arc, OnceLock};

use sunscreen_gpu_runtime::{Allocation, AsKernelArg, GpuRuntime, Grid, launch_kernel};

#[cfg(any(feature = "test_kernels", test))]
pub(crate) const GPU_KERNELS: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/sunscreen_tfhe_gpu.test.fatbin"));

#[cfg(test)]
mod tests;

use sunscreen_gpu_runtime::Result;

#[doc(hidden)]
pub fn get_runtimes() -> Arc<Vec<Arc<GpuRuntime>>> {
    static RUNTIMES: OnceLock<Arc<Vec<Arc<GpuRuntime>>>> = OnceLock::new();

    RUNTIMES
        .get_or_init(|| {
            sunscreen_gpu_runtime::init_runtimes(GPU_KERNELS);
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
                    (r, stream)
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
