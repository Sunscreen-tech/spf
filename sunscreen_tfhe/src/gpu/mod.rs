use std::sync::OnceLock;

use sunscreen_gpu_runtime::{Allocation, AsKernelArg, DeviceId, GpuRuntime, Grid, launch_kernel};

#[cfg(any(feature = "test_kernels", test))]
pub(crate) const GPU_KERNELS: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/sunscreen_tfhe_gpu.test.fatbin"));

#[cfg(test)]
mod tests;

use sunscreen_gpu_runtime::Result;

#[cfg(any(feature = "test_kernels", test))]
#[doc(hidden)]
pub mod test_utils {
    use std::{
        ops::Deref,
        sync::{Arc, OnceLock},
    };

    use sunscreen_gpu_runtime::GpuRuntime;

    #[cfg(feature = "cuda")]
    use sunscreen_gpu_runtime::cuda_runtime::CudaRuntime;

    use super::GPU_KERNELS;

    pub fn get_runtimes() -> Arc<Vec<GpuRuntime>> {
        static RUNTIMES: OnceLock<Arc<Vec<GpuRuntime>>> = OnceLock::new();

        RUNTIMES
            .get_or_init(|| {
                let runtimes: Vec<GpuRuntime> = vec![
                    #[cfg(feature = "cuda")]
                    GpuRuntime::new(CudaRuntime::new(GPU_KERNELS).unwrap()),
                ];

                Arc::new(runtimes)
            })
            .clone()
    }

    #[derive(Clone, Copy, Debug)]
    pub struct PolyDegreeInfo(pub u32);

    impl PolyDegreeInfo {
        pub fn threads_per_block(&self) -> u32 {
            self.0 / 8
        }
    }

    impl From<u32> for PolyDegreeInfo {
        fn from(value: u32) -> Self {
            assert!(value.is_power_of_two());

            Self(value)
        }
    }

    impl Deref for PolyDegreeInfo {
        type Target = u32;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    pub const SUPPORTED_POLY_DEGREES: &[PolyDegreeInfo] = &[PolyDegreeInfo(2048u32)];
}

/// Scratch space used during GPU computation.
pub struct Scratch {
    alloc: Allocation<u8>,
}

impl Scratch {
    /// Allocate a new scratch buffer compatible with the given launch grid.
    pub fn new<G: Grid>(r: &GpuRuntime, grid: G) -> Result<Self> {
        static SIZE: OnceLock<u32> = OnceLock::new();

        let size_per_block = *SIZE.get_or_init(|| {
            let size = r.allocate::<u32>(1).unwrap();

            let stream = r.make_stream().unwrap();

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
            alloc: r.allocate::<u8>((size_per_block * num_blocks) as usize)?,
        })
    }
}

impl AsKernelArg for Scratch {
    fn as_kernel_arg(&self) -> *const std::ffi::c_void {
        self.alloc.as_kernel_arg()
    }
}
