#[derive(Debug, thiserror::Error)]
/// Errors that can occur in this crate.
pub enum Error {
    /// Attempted an operation using an incorrect ciphertext type.
    #[error("Ciphertext was not of the expected type.")]
    CiphertextMismatch,

    /// A serialization error.
    #[error("{0}")]
    Bincode(#[from] bincode::Error),

    /// An error in the underlying `sunscreen_tfhe` crypto library.
    #[error("{0}")]
    SunscreenTfhe(#[from] sunscreen_tfhe::Error),
}

/// A `Result` for this crate.
pub type Result<T> = std::result::Result<T, Error>;
