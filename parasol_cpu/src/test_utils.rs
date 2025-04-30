use std::sync::{Arc, OnceLock};

use parasol_runtime::{
    DEFAULT_80, DEFAULT_128, Encryption, Evaluation, L1GlweCiphertext, SecretKey,
    fluent::UInt,
    test_utils::{get_compute_key_80, get_compute_key_128},
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

/// Create a computer with the default encryption and evaluation.
pub fn make_computer_80() -> (FheComputer, Encryption) {
    let compute_key = get_compute_key_80();
    let enc = Encryption::new(&DEFAULT_80);
    let eval = Evaluation::new(compute_key, &DEFAULT_80, &enc);

    (
        FheComputer::new_with_threadpool(&enc, &eval, get_thread_pool()),
        enc,
    )
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

pub trait Bits<const N: usize> {
    type PlaintextType: num::Num
        + TryFrom<u64, Error = std::num::TryFromIntError>
        + Into<u64>
        + std::fmt::Debug
        + Copy
        + ToArg;
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
{
    Plain(<BitsUnsigned as Bits<N>>::PlaintextType),
    Encrypted(UInt<N, L1GlweCiphertext>),
}

impl<const N: usize> std::fmt::Debug for MaybeEncryptedUInt<N>
where
    BitsUnsigned: Bits<N>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MaybeEncryptedUInt {{ .. }}")
    }
}

impl<const N: usize> MaybeEncryptedUInt<N>
where
    BitsUnsigned: Bits<N>,
{
    pub fn new(val: u64, enc: &Encryption, sk: &SecretKey, encrypt: bool) -> Self {
        if !encrypt {
            Self::Plain(val.try_into().unwrap())
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
                <BitsUnsigned as Bits<N>>::PlaintextType::try_from(x.decrypt(enc, sk)).unwrap()
            }
        }
    }
}

impl<const N: usize> ToArg for MaybeEncryptedUInt<N>
where
    BitsUnsigned: Bits<N>,
{
    const ALIGNMENT: usize = <BitsUnsigned as Bits<N>>::PlaintextType::ALIGNMENT;
    const SIZE: usize = <BitsUnsigned as Bits<N>>::PlaintextType::SIZE;
    const SIGNED: bool = false;

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

#[cfg(test)]
mod tests {
    use parasol_runtime::test_utils::{get_encryption_80, get_secret_keys_80};

    use super::MaybeEncryptedUInt;

    #[test]
    fn can_roundtrip_maybeuint() {
        let enc = get_encryption_80();
        let sk = get_secret_keys_80();

        for i in 0..10 {
            let val = MaybeEncryptedUInt::<8>::new(i, &enc, &sk, i % 2 == 0);
            assert_eq!(val.get(&enc, &sk), i as u8);
        }
    }
}
