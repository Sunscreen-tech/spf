#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Ciphertext was not of the expected type.")]
    CiphertextMismatch,

    #[error("{0}")]
    Bincode(#[from] bincode::Error),

    #[error("{0}")]
    SunscreenTfhe(#[from] sunscreen_tfhe::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
