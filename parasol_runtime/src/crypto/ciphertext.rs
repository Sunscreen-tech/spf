use super::{
    L0LweCiphertext, L1GgswCiphertext, L1GlevCiphertext, L1GlweCiphertext, L1LweCiphertext,
};
use crate::error::Error;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum CiphertextType {
    L0LweCiphertext = 0,
    L1LweCiphertext = 1,
    L1GlweCiphertext = 2,
    L1GgswCiphertext = 3,
    L1GlevCiphertext = 4,
}

#[derive(Clone)]
pub enum Ciphertext {
    L0LweCiphertext(L0LweCiphertext),
    L1LweCiphertext(L1LweCiphertext),
    L1GlweCiphertext(L1GlweCiphertext),
    L1GgswCiphertext(L1GgswCiphertext),
    L1GlevCiphertext(L1GlevCiphertext),
}

impl Ciphertext {
    pub fn borrow_lwe0(&self) -> &L0LweCiphertext {
        match self {
            Self::L0LweCiphertext(x) => x,
            _ => panic!("Ciphertext was not L0LweCiphertext"),
        }
    }

    pub fn borrow_lwe1(&self) -> &L1LweCiphertext {
        match self {
            Self::L1LweCiphertext(x) => x,
            _ => panic!("Ciphertext was not L1LweCiphertext"),
        }
    }

    pub fn borrow_glwe1(&self) -> &L1GlweCiphertext {
        match self {
            Self::L1GlweCiphertext(x) => x,
            _ => panic!("Ciphertext was not L1GlweCiphertext"),
        }
    }

    pub fn borrow_ggsw1(&self) -> &L1GgswCiphertext {
        match self {
            Self::L1GgswCiphertext(x) => x,
            _ => panic!("Ciphertext was not L1GgswCiphertext"),
        }
    }

    pub fn borrow_glev1(&self) -> &L1GlevCiphertext {
        match self {
            Self::L1GlevCiphertext(x) => x,
            _ => panic!("Ciphertext was not L1GlevCiphertext"),
        }
    }
}

impl From<L0LweCiphertext> for Ciphertext {
    fn from(value: L0LweCiphertext) -> Self {
        Ciphertext::L0LweCiphertext(value)
    }
}

impl From<L1LweCiphertext> for Ciphertext {
    fn from(value: L1LweCiphertext) -> Self {
        Ciphertext::L1LweCiphertext(value)
    }
}

impl From<L1GlweCiphertext> for Ciphertext {
    fn from(value: L1GlweCiphertext) -> Self {
        Ciphertext::L1GlweCiphertext(value)
    }
}

impl From<L1GgswCiphertext> for Ciphertext {
    fn from(value: L1GgswCiphertext) -> Self {
        Ciphertext::L1GgswCiphertext(value)
    }
}

impl From<L1GlevCiphertext> for Ciphertext {
    fn from(value: L1GlevCiphertext) -> Self {
        Ciphertext::L1GlevCiphertext(value)
    }
}

impl TryInto<L0LweCiphertext> for Ciphertext {
    type Error = Error;

    fn try_into(self) -> Result<L0LweCiphertext, Self::Error> {
        match self {
            Self::L0LweCiphertext(x) => Ok(x),
            _ => Err(Error::CiphertextMismatch),
        }
    }
}

impl TryInto<L1LweCiphertext> for Ciphertext {
    type Error = Error;

    fn try_into(self) -> Result<L1LweCiphertext, Self::Error> {
        match self {
            Self::L1LweCiphertext(x) => Ok(x),
            _ => Err(Error::CiphertextMismatch),
        }
    }
}

impl TryInto<L1GlweCiphertext> for Ciphertext {
    type Error = Error;

    fn try_into(self) -> Result<L1GlweCiphertext, Self::Error> {
        match self {
            Self::L1GlweCiphertext(x) => Ok(x),
            _ => Err(Error::CiphertextMismatch),
        }
    }
}

impl TryInto<L1GgswCiphertext> for Ciphertext {
    type Error = Error;

    fn try_into(self) -> Result<L1GgswCiphertext, Self::Error> {
        match self {
            Self::L1GgswCiphertext(x) => Ok(x),
            _ => Err(Error::CiphertextMismatch),
        }
    }
}

impl TryInto<L1GlevCiphertext> for Ciphertext {
    type Error = Error;

    fn try_into(self) -> Result<L1GlevCiphertext, Self::Error> {
        match self {
            Self::L1GlevCiphertext(x) => Ok(x),
            _ => Err(Error::CiphertextMismatch),
        }
    }
}
