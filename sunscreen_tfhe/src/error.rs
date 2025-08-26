/// Errors that can occur using this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The size of the given entity is invalid under the given scheme parameters.
    #[error("The given entity is the incorrect size for the requested parameters.")]
    InvalidSize,

    #[cfg(feature = "gpu")]
    #[error("GPU error: {0}")]
    /// An error occurred when performing an operation on the GPU.
    GpuError(#[from] sunscreen_gpu_runtime::Error),
}

/// A result that can occur in this crate.
pub type Result<T> = std::result::Result<T, Error>;
