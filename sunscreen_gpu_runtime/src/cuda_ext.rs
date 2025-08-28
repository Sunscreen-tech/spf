use cuda_driver_sys::{CUdeviceptr, CUresult, CUstream};

unsafe extern "C" {
    pub fn cuMemFreeAsync(ptr: CUdeviceptr, h_stream: CUstream) -> CUresult;
}
