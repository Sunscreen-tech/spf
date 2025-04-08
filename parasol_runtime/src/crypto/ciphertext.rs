use super::{
    L0LweCiphertext, L1GgswCiphertext, L1GlevCiphertext, L1GlweCiphertext, L1LweCiphertext,
};
use crate::error::Error;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
/// An enum of possible ciphertext types.
pub enum CiphertextType {
    /// Indicates an [`L0LweCiphertext`]
    L0LweCiphertext = 0,

    /// Indicates an [`L1LweCiphertext`]
    L1LweCiphertext = 1,

    /// Indicates an [`L1GlweCiphertext`]
    L1GlweCiphertext = 2,

    /// Indicates an [`L1GgswCiphertext`]
    L1GgswCiphertext = 3,

    /// Indicates an [`L1GlevCiphertext`]
    L1GlevCiphertext = 4,
}

#[derive(Clone)]
pub enum Ciphertext {
    L0Lwe(L0LweCiphertext),
    L1Lwe(L1LweCiphertext),
    L1Glwe(L1GlweCiphertext),
    L1Ggsw(L1GgswCiphertext),
    L1Glev(L1GlevCiphertext),
}

impl Ciphertext {
    pub fn borrow_lwe0(&self) -> &L0LweCiphertext {
        match self {
            Self::L0Lwe(x) => x,
            _ => panic!("Ciphertext was not L0LweCiphertext"),
        }
    }

    pub fn borrow_lwe1(&self) -> &L1LweCiphertext {
        match self {
            Self::L1Lwe(x) => x,
            _ => panic!("Ciphertext was not L1LweCiphertext"),
        }
    }

    pub fn borrow_glwe1(&self) -> &L1GlweCiphertext {
        match self {
            Self::L1Glwe(x) => x,
            _ => panic!("Ciphertext was not L1GlweCiphertext"),
        }
    }

    pub fn borrow_ggsw1(&self) -> &L1GgswCiphertext {
        match self {
            Self::L1Ggsw(x) => x,
            _ => panic!("Ciphertext was not L1GgswCiphertext"),
        }
    }

    pub fn borrow_glev1(&self) -> &L1GlevCiphertext {
        match self {
            Self::L1Glev(x) => x,
            _ => panic!("Ciphertext was not L1GlevCiphertext"),
        }
    }
}

impl From<L0LweCiphertext> for Ciphertext {
    fn from(value: L0LweCiphertext) -> Self {
        Ciphertext::L0Lwe(value)
    }
}

impl From<L1LweCiphertext> for Ciphertext {
    fn from(value: L1LweCiphertext) -> Self {
        Ciphertext::L1Lwe(value)
    }
}

impl From<L1GlweCiphertext> for Ciphertext {
    fn from(value: L1GlweCiphertext) -> Self {
        Ciphertext::L1Glwe(value)
    }
}

impl From<L1GgswCiphertext> for Ciphertext {
    fn from(value: L1GgswCiphertext) -> Self {
        Ciphertext::L1Ggsw(value)
    }
}

impl From<L1GlevCiphertext> for Ciphertext {
    fn from(value: L1GlevCiphertext) -> Self {
        Ciphertext::L1Glev(value)
    }
}

impl TryInto<L0LweCiphertext> for Ciphertext {
    type Error = Error;

    fn try_into(self) -> Result<L0LweCiphertext, Self::Error> {
        match self {
            Self::L0Lwe(x) => Ok(x),
            _ => Err(Error::CiphertextMismatch),
        }
    }
}

impl TryInto<L1LweCiphertext> for Ciphertext {
    type Error = Error;

    fn try_into(self) -> Result<L1LweCiphertext, Self::Error> {
        match self {
            Self::L1Lwe(x) => Ok(x),
            _ => Err(Error::CiphertextMismatch),
        }
    }
}

impl TryInto<L1GlweCiphertext> for Ciphertext {
    type Error = Error;

    fn try_into(self) -> Result<L1GlweCiphertext, Self::Error> {
        match self {
            Self::L1Glwe(x) => Ok(x),
            _ => Err(Error::CiphertextMismatch),
        }
    }
}

impl TryInto<L1GgswCiphertext> for Ciphertext {
    type Error = Error;

    fn try_into(self) -> Result<L1GgswCiphertext, Self::Error> {
        match self {
            Self::L1Ggsw(x) => Ok(x),
            _ => Err(Error::CiphertextMismatch),
        }
    }
}

impl TryInto<L1GlevCiphertext> for Ciphertext {
    type Error = Error;

    fn try_into(self) -> Result<L1GlevCiphertext, Self::Error> {
        match self {
            Self::L1Glev(x) => Ok(x),
            _ => Err(Error::CiphertextMismatch),
        }
    }
}
