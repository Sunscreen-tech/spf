use std::sync::{Arc, OnceLock};

use parasol_runtime::{
    DEFAULT_128, Encryption, Evaluation, L1GlweCiphertext, SecretKey,
    fluent::{Int, UInt},
    test_utils::get_compute_key_128,
};
use rayon::{ThreadPool, ThreadPoolBuilder};
use sunscreen_tfhe::entities::Polynomial;

use crate::{Byte, FheComputer, ToArg};

pub fn poly_one() -> Arc<Polynomial<u64>> {
    static ONE: OnceLock<Arc<Polynomial<u64>>> = OnceLock::new();

    ONE.get_or_init(|| {
        let mut coeffs = vec![0; 1024];
        coeffs[0] = 1;
        Arc::new(Polynomial::new(&coeffs))
    })
    .clone()
}

pub fn get_thread_pool() -> Arc<ThreadPool> {
    static THREAD_POOL: OnceLock<Arc<ThreadPool>> = OnceLock::new();

    THREAD_POOL
        .get_or_init(|| {
            Arc::new(
                ThreadPoolBuilder::new()
                    .thread_name(|x| format!("Fhe worker {x}"))
                    .build()
                    .unwrap(),
            )
        })
        .clone()
}

pub fn make_computer_128() -> (FheComputer, Encryption) {
    let compute_key = get_compute_key_128();
    let enc = Encryption::new(&DEFAULT_128);
    let eval = Evaluation::new(compute_key, &DEFAULT_128, &enc);

    (
        FheComputer::new_with_threadpool(&enc, &eval, get_thread_pool()),
        enc,
    )
}

pub trait TestFrom<T> {
    fn test_from(value: T) -> Self;
}

macro_rules! impl_test_from {
    ( $( $x:ty ),* ) => {
        $(
            impl TestFrom<u64> for $x {
                fn test_from(value: u64) -> Self {
                    value as $x
                }
            }
        )*
    };
}

impl_test_from!(u32, u16, u8);
impl_test_from!(i32, i16, i8);

pub trait Bits<const N: usize> {
    type PlaintextType: num::Num + TestFrom<u64> + std::fmt::Debug + Copy + ToArg;
}

pub struct BitsUnsigned();

impl Bits<32> for BitsUnsigned {
    type PlaintextType = u32;
}

impl Bits<16> for BitsUnsigned {
    type PlaintextType = u16;
}

impl Bits<8> for BitsUnsigned {
    type PlaintextType = u8;
}

pub enum MaybeEncryptedUInt<const N: usize>
where
    BitsUnsigned: Bits<N>,
    <BitsUnsigned as Bits<N>>::PlaintextType: Into<u64>,
{
    Plain(<BitsUnsigned as Bits<N>>::PlaintextType),
    Encrypted(UInt<N, L1GlweCiphertext>),
}

impl<const N: usize> std::fmt::Debug for MaybeEncryptedUInt<N>
where
    BitsUnsigned: Bits<N>,
    <BitsUnsigned as Bits<N>>::PlaintextType: Into<u64>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MaybeEncryptedUInt {{ .. }}")
    }
}

impl<const N: usize> MaybeEncryptedUInt<N>
where
    BitsUnsigned: Bits<N>,
    <BitsUnsigned as Bits<N>>::PlaintextType: Into<u64>,
{
    pub fn new(val: u64, enc: &Encryption, sk: &SecretKey, encrypt: bool) -> Self {
        if !encrypt {
            Self::Plain(<BitsUnsigned as Bits<N>>::PlaintextType::test_from(val))
        } else {
            Self::Encrypted(UInt::encrypt_secret(val, enc, sk))
        }
    }

    pub fn get(
        &self,
        enc: &Encryption,
        sk: &SecretKey,
    ) -> <BitsUnsigned as Bits<N>>::PlaintextType {
        match self {
            Self::Plain(x) => *x,
            Self::Encrypted(x) => {
                <BitsUnsigned as Bits<N>>::PlaintextType::test_from(x.decrypt(enc, sk))
            }
        }
    }
}

impl<const N: usize> ToArg for MaybeEncryptedUInt<N>
where
    BitsUnsigned: Bits<N>,
    <BitsUnsigned as Bits<N>>::PlaintextType: Into<u64>,
{
    fn alignment() -> usize {
        <BitsUnsigned as Bits<N>>::PlaintextType::alignment()
    }

    fn size() -> usize {
        <BitsUnsigned as Bits<N>>::PlaintextType::size()
    }

    fn to_bytes(&self) -> Vec<Byte> {
        match self {
            Self::Plain(x) => x.to_bytes(),
            Self::Encrypted(x) => x.to_bytes(),
        }
    }

    fn try_from_bytes(data: Vec<crate::Byte>) -> crate::Result<Self> {
        match &data[0] {
            Byte::Plaintext(_) => Ok(Self::Plain(
                <<BitsUnsigned as Bits<N>>::PlaintextType>::try_from_bytes(data)?,
            )),
            Byte::Ciphertext(_) => Ok(Self::Encrypted(UInt::try_from_bytes(data)?)),
        }
    }
}

pub struct BitsSigned();

impl Bits<32> for BitsSigned {
    type PlaintextType = i32;
}

impl Bits<16> for BitsSigned {
    type PlaintextType = i16;
}

impl Bits<8> for BitsSigned {
    type PlaintextType = i8;
}

pub enum MaybeEncryptedInt<const N: usize>
where
    BitsSigned: Bits<N>,
    <BitsSigned as Bits<N>>::PlaintextType: Into<i64>,
{
    Plain(<BitsSigned as Bits<N>>::PlaintextType),
    Encrypted(Int<N, L1GlweCiphertext>),
}

impl<const N: usize> std::fmt::Debug for MaybeEncryptedInt<N>
where
    BitsSigned: Bits<N>,
    <BitsSigned as Bits<N>>::PlaintextType: Into<i64>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MaybeEncryptedInt {{ .. }}")
    }
}

impl<const N: usize> MaybeEncryptedInt<N>
where
    BitsSigned: Bits<N>,
    <BitsSigned as Bits<N>>::PlaintextType: Into<i64>,
{
    pub fn new(val: u64, enc: &Encryption, sk: &SecretKey, encrypt: bool) -> Self {
        if !encrypt {
            Self::Plain(<BitsSigned as Bits<N>>::PlaintextType::test_from(val))
        } else {
            Self::Encrypted(Int::encrypt_secret(val, enc, sk))
        }
    }

    pub fn get(&self, enc: &Encryption, sk: &SecretKey) -> <BitsSigned as Bits<N>>::PlaintextType {
        match self {
            Self::Plain(x) => *x,
            Self::Encrypted(x) => {
                <BitsSigned as Bits<N>>::PlaintextType::test_from(x.decrypt(enc, sk))
            }
        }
    }
}

impl<const N: usize> ToArg for MaybeEncryptedInt<N>
where
    BitsSigned: Bits<N>,
    <BitsSigned as Bits<N>>::PlaintextType: Into<i64>,
{
    fn alignment() -> usize {
        <BitsSigned as Bits<N>>::PlaintextType::size()
    }

    fn size() -> usize {
        <BitsSigned as Bits<N>>::PlaintextType::size()
    }

    fn to_bytes(&self) -> Vec<Byte> {
        match self {
            Self::Plain(x) => x.to_bytes(),
            Self::Encrypted(x) => x.to_bytes(),
        }
    }

    fn try_from_bytes(data: Vec<crate::Byte>) -> crate::Result<Self> {
        match &data[0] {
            Byte::Plaintext(_) => Ok(Self::Plain(
                <<BitsSigned as Bits<N>>::PlaintextType>::try_from_bytes(data)?,
            )),
            Byte::Ciphertext(_) => Ok(Self::Encrypted(Int::try_from_bytes(data)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use parasol_runtime::test_utils::{get_encryption_128, get_secret_keys_128};

    use super::{MaybeEncryptedInt, MaybeEncryptedUInt};

    #[test]
    fn can_roundtrip_maybeuint() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();

        for i in 0..10 {
            let val = MaybeEncryptedUInt::<8>::new(i, &enc, &sk, i % 2 == 0);
            assert_eq!(val.get(&enc, &sk), i as u8);
        }
    }

    #[test]
    fn can_roundtrip_maybeint() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();

        for i in 118..138 {
            let val = MaybeEncryptedInt::<8>::new(i, &enc, &sk, i % 2 == 0);
            assert_eq!(val.get(&enc, &sk), i as i8);
        }
    }
}
