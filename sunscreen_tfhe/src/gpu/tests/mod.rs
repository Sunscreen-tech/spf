use std::sync::{Arc, OnceLock};

use sunscreen_gpu_runtime::GpuRuntime;

#[cfg(feature = "cuda")]
use sunscreen_gpu_runtime::cuda_runtime::CudaRuntime;

#[cfg(feature = "cuda")]
use crate::gpu::GPU_KERNELS;

mod fft;

pub(crate) fn get_runtimes() -> Arc<Vec<GpuRuntime>> {
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
