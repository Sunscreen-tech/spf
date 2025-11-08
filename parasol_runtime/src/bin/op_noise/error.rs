use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Error {
    TooMuchNoise,
}

pub type Result<T> = std::result::Result<T, Error>;
