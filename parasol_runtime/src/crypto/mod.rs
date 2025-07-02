pub mod ciphertext;
mod encryption;
mod evaluation;
mod keys;

/// Recryption is the process of homomorphically computing an encryption under
/// a different algorithm. When the resulting FHE ciphertext is decrypted,
/// the resulting message is then a ciphertext under a that algorithm.
///
/// For example, we can produce an FHE encryption of a one-time pad `s`, encrypt
/// `s` under FHE, then homomorphically XOR `s` with the message. This produces
/// an FHE ciphertext whose message contains a one-time pad encryption of m under
/// OTP key `s`. When we decrypt the FHE ciphertext, the resulting message is
/// still encrypted under `s` and only its owner can view the final message.
///
/// This is useful in threshold encryption settings where the user wishes to
/// view the result of an FHE computation without revealing it; without this
/// technique the threshold committee would see the result.
pub mod recryption;

pub use encryption::*;
pub use evaluation::*;
pub use keys::*;
pub use recryption::*;

/// A trait that produces a trivial zero encryption for the implementing ciphertext type.
pub trait TrivialZero
where
    Self: Sized,
{
    /// Produce a trivial encryption of zero.
    fn trivial_zero(enc: &Encryption) -> Self;
}

/// A trait that produces a trivial one encryption for the implementing ciphertext type.
pub trait TrivialOne
where
    Self: Sized,
{
    /// Produce a trivial encryption of one.
    fn trivial_one(enc: &Encryption) -> Self;
}

macro_rules! impl_trivial_int {
    ($itype:ty) => {
        impl TrivialZero for $itype {
            fn trivial_zero(_enc: &Encryption) -> Self {
                0
            }
        }

        impl TrivialOne for $itype {
            fn trivial_one(_enc: &Encryption) -> Self {
                1
            }
        }
    };
}

impl_trivial_int! {u8}
impl_trivial_int! {u16}
impl_trivial_int! {u32}
impl_trivial_int! {u64}
impl_trivial_int! {u128}
impl_trivial_int! {i8}
impl_trivial_int! {i16}
impl_trivial_int! {i32}
impl_trivial_int! {i64}
impl_trivial_int! {i128}
