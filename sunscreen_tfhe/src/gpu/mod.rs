#[cfg(any(feature = "test_kernels", test))]
pub(crate) const GPU_KERNELS: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/sunscreen_tfhe_gpu.test.fatbin"));

#[cfg(test)]
mod tests;

#[cfg(any(feature = "test_kernels", test))]
#[doc(hidden)]
pub mod test_utils {
    use std::sync::{Arc, OnceLock};

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
}
