#[cfg(feature = "cuda")]
use cuda_runtime_sys::cudaError;

#[cfg(feature = "cuda")]
use cuda_driver_sys::cudaError_enum;

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[cfg(feature = "cuda")]
    #[error("Cuda error: {0:#?}")]
    CudaError(String),

    #[error("The given device id was invalid")]
    InvalidDevice,

    #[error("The given CString contained internal null characters.")]
    NulError,

    #[error("The grid specification is not allowed for the given runtime.")]
    IllegalGrid,

    #[error("Could not cast the given slice")]
    CastError,

    #[error("No such kernel.")]
    NoSuchKernel,
}

impl Error {
    #[cfg(feature = "cuda")]
    pub fn cuda_runtime_err(e: cudaError) -> Self {
        use std::ffi::CStr;

        let e = unsafe {
            let e = cuda_runtime_sys::cudaGetErrorName(e);
            let err_str = CStr::from_ptr(e);
            err_str.to_string_lossy()
        };

        Self::CudaError(e.to_string())
    }

    #[cfg(feature = "cuda")]
    pub fn cuda_driver_err(e: cudaError_enum) -> Self {
        use std::ffi::CStr;

        let e = unsafe {
            let mut err_str: *const i8 = std::ptr::null_mut();

            cuda_driver_sys::cuGetErrorString(e, &raw mut err_str);
            let err_str = CStr::from_ptr(err_str);
            err_str.to_string_lossy()
        };

        Self::CudaError(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
