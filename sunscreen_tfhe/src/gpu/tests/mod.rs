use std::sync::{Arc, OnceLock};

use sunscreen_gpu_runtime::GpuRuntimeBackend;

#[cfg(feature = "cuda")]
use sunscreen_gpu_runtime::cuda_runtime::CudaRuntime;

#[cfg(feature = "cuda")]
use crate::gpu::GPU_KERNELS;

mod fft;

pub(crate) fn get_runtimes() -> Arc<Vec<Arc<dyn GpuRuntimeBackend>>> {
    static RUNTIMES: OnceLock<Arc<Vec<Arc<dyn GpuRuntimeBackend>>>> = OnceLock::new();

    RUNTIMES
        .get_or_init(|| {
            let mut runtimes: Vec<Arc<dyn GpuRuntimeBackend>> = vec![];

            #[cfg(feature = "cuda")]
            runtimes.push(Arc::new(CudaRuntime::new(GPU_KERNELS).unwrap()));

            Arc::new(runtimes)
        })
        .clone()
}
