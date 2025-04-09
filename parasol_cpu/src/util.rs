use crate::Result;

/// A trait for converting data to and from buffers usable with an [`FheComputer`](crate::FheComputer).
/// # Remarks
/// You should usually `derive(IntoBytes)` for any struct type you want to use
/// with an [`FheComputer`](crate::FheComputer). While ISA's size and
/// alignment rules are simple, they're annoying.
///
/// The data layout in the buffer from the perspective of the
/// [`FheComputer`](crate::FheComputer) is as if this struct was declared
/// with #[repr(C)]. It's generally advisable, but not required to add this to
/// your type.
pub trait IntoBytes
where
    Self: Sized,
{
    /// The required alignment for this
    fn alignment() -> usize;

    /// The size of this type.
    fn size() -> usize;

    /// Convert this type into a buffer format with satisfied size and alignment
    /// requirements for use in an [`FheComputer`](crate::FheComputer).
    fn try_into_bytes(&self, data: &mut [u8]) -> Result<()>;

    /// Convert a byte array into this type.
    fn try_from_bytes(data: &[u8]) -> Result<Self>;
}

macro_rules! impl_into_bytes {
    ($ty:ty,$align:expr,$size:expr) => {
        impl crate::IntoBytes for $ty {
            fn alignment() -> usize {
                $align
            }

            fn size() -> usize {
                $size
            }

            fn try_into_bytes(&self, data: &mut [u8]) -> crate::Result<()> {
                if data.len() != Self::size() {
                    return Err(crate::Error::buffer_size_mismatch());
                }

                data.clone_from_slice(&self.to_le_bytes());

                Ok(())
            }

            fn try_from_bytes(data: &[u8]) -> crate::Result<Self> {
                if data.len() != Self::size() {
                    return Err(crate::Error::buffer_size_mismatch());
                }

                Ok(Self::from_le_bytes(data.try_into().unwrap()))
            }
        }
    };
}

impl_into_bytes!(i8, 1usize, 1usize);
impl_into_bytes!(i16, 2usize, 2usize);
impl_into_bytes!(i32, 4usize, 4usize);
impl_into_bytes!(i64, 8usize, 8usize);
impl_into_bytes!(i128, 16usize, 16usize);
impl_into_bytes!(u8, 1usize, 1usize);
impl_into_bytes!(u16, 2usize, 2usize);
impl_into_bytes!(u32, 4usize, 4usize);
impl_into_bytes!(u64, 8usize, 8usize);
impl_into_bytes!(u128, 16usize, 16usize);

pub trait FheBuffer
where
    Self: Sized,
{
    fn clone_into_plaintext(&self) -> Vec<u8>;

    fn try_from_plaintext(data: &[u8]) -> Result<Self>;
}

impl<T> FheBuffer for T
where
    T: IntoBytes,
{
    fn try_from_plaintext(data: &[u8]) -> Result<Self> {
        T::try_from_bytes(data)
    }

    fn clone_into_plaintext(&self) -> Vec<u8> {
        let mut data = vec![0u8; T::size()];

        T::try_into_bytes(self, &mut data).unwrap();

        data
    }
}

impl<T> FheBuffer for Vec<T>
where
    T: IntoBytes,
{
    fn try_from_plaintext(data: &[u8]) -> Result<Self> {
        data.chunks(T::size())
            .map(|x| T::try_from_bytes(x))
            .collect()
    }

    fn clone_into_plaintext(&self) -> Vec<u8> {
        let mut data = vec![0u8; self.len() * T::size()];

        for (i, c) in data.chunks_mut(T::size()).enumerate() {
            self[i].try_into_bytes(c).unwrap();
        }

        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate as tfhe_cpu;
    use crate::IntoBytes;

    #[test]
    fn correct_size_alignment() {
        #[derive(IntoBytes)]
        struct Bar {
            a: u8,  // 1 + 1 bytes
            b: u16, // 2 bytes
            c: u8,  // 1 + 3 bytes
            d: u32, // 4 bytes
            e: u8,  // 1 + 3 bytes
            f: u64, // 8 bytes
        }

        assert_eq!(Bar::size(), 24);
        assert_eq!(Bar::alignment(), 8);
    }

    #[test]
    fn can_roundtrip() {
        #[derive(IntoBytes, Debug, PartialEq, Eq)]
        struct Bar {
            a: u8,  // 1 + 1 bytes
            b: u16, // 2 bytes
            c: u8,  // 1 + 3 bytes
            d: u32, // 4 bytes
            e: u8,  // 1 + 3 bytes
            f: u64, // 8 bytes
        }

        let x = Bar {
            a: 1,
            b: 2,
            c: 3,
            d: 4,
            e: 5,
            f: 6,
        };

        let mut data = vec![0u8; Bar::size()];

        x.try_into_bytes(&mut data).unwrap();
        let y = Bar::try_from_bytes(&data).unwrap();

        assert_eq!(x, y);
    }

    #[test]
    fn nested_structs() {
        #[derive(IntoBytes)]
        struct Bar {
            a: u8,  // 1 + 1 bytes
            b: u16, // 2 bytes
            c: u8,  // 1 + 3 bytes
            d: u32, // 4 bytes
            e: u8,  // 1 + 3 bytes
            f: u64, // 8 bytes
        }

        #[derive(IntoBytes)]
        struct Baz {
            a: Bar,
            b: Bar,
        }

        assert_eq!(Bar::size(), 24);
        assert_eq!(Bar::alignment(), 8);

        assert_eq!(Baz::size(), 48);
        assert_eq!(Baz::alignment(), 8);
    }

    #[test]
    fn can_roundtrip_plaintext() {
        #[derive(IntoBytes, Debug, PartialEq, Eq)]
        struct Bar {
            a: u8,  // 1 + 1 bytes
            b: u16, // 2 bytes
            c: u8,  // 1 + 3 bytes
            d: u32, // 4 bytes
        }

        let x = vec![
            Bar {
                a: 1,
                b: 2,
                c: 3,
                d: 4,
            },
            Bar {
                a: 5,
                b: 6,
                c: 7,
                d: 8,
            },
            Bar {
                a: 9,
                b: 10,
                c: 11,
                d: 12,
            },
        ];

        let y = Vec::<Bar>::try_from_plaintext(&x.clone_into_plaintext()).unwrap();

        assert_eq!(x, y);
    }
}
