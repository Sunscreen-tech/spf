pub mod ciphertext;
mod encryption;
mod evaluation;
mod keys;

pub use encryption::*;
pub use evaluation::*;
pub use keys::*;

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
