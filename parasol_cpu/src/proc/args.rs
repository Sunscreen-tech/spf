use std::marker::PhantomData;

use crate::Byte;
use crate::{Error, Result};
use parasol_runtime::{
    L1GlweCiphertext,
    fluent::{DynamicInt, DynamicUInt, Int, UInt},
};
use paste::paste;

// TODO: Should profile some apps, but we can likely avoid a bunch of copying
/// A trait specifying how to convert this value to a form that can be passed as an FHE program
/// argument.
pub trait ToArg
where
    Self: Sized,
{
    /// The required alignment for this type. Must be power of 2 and should be no larger than 4096.
    fn alignment() -> usize;

    /// The number of bytes this type takes. Should be no greater than `u32::MAX`.
    fn size() -> usize;

    /// Convert a byte array and metadata into an [`Arg`] indicating the alignment,
    /// size.
    fn bytes_to_arg(bytes: Vec<Byte>) -> Arg {
        Arg {
            alignment: Self::alignment(),
            bytes,
        }
    }

    /// Convert this value into a [`Vec<Byte>`].
    ///
    /// # Remarks
    /// The number of bytes returned must equal `T::size()` or panics may result in related
    /// methods.
    fn to_bytes(&self) -> Vec<Byte>;

    /// Convert this value into an [`Arg`] for calling with a function.
    /// This allows parasol to understand how to pass arguments to a program.
    ///
    /// See [here](https://drive.google.com/file/d/1Ja_Tpp_5Me583CGVD-BIZMlgGBnlKU4R/view?pli=1) for
    /// details.
    ///
    /// # Panics
    /// If `self.to_bytes().len() != Self::size()`.
    fn to_arg(&self) -> Arg {
        let bytes = self.to_bytes();

        assert_eq!(bytes.len(), Self::size());

        Self::bytes_to_arg(bytes)
    }

    /// Describe this type when it appears in the return value of a function call.
    /// This allows the Parasol processor to understand how to capture the return value from a
    /// program.
    ///
    /// See [here](https://drive.google.com/file/d/1Ja_Tpp_5Me583CGVD-BIZMlgGBnlKU4R/view?pli=1) for
    /// details.
    fn to_return_value() -> ReturnValue<Self> {
        ReturnValue {
            alignment: Self::alignment(),
            size: Self::size(),
            _phantom: PhantomData,
        }
    }

    /// Attempt to create a value of this type from the given bytes.
    fn try_from_bytes(data: Vec<Byte>) -> Result<Self>;
}

/// Similar to [`ToArg`] but the alignment and size are figured out from the instance not just the type
pub trait DynamicToArg
where
    Self: Sized,
{
    /// The required alignment for this type. Must be power of 2 and should be no larger than 4096.
    fn alignment(&self) -> usize;

    /// The number of bytes this type takes. Should be no greater than `u32::MAX`.
    fn size(&self) -> usize;

    /// Whether this type needs to be sign extended or not.
    fn is_signed() -> bool;

    /// Convert this value into a [`Vec<Byte>`].
    ///
    /// # Remarks
    /// The number of bytes returned must equal `self.size()` or panics may result in related
    /// methods.
    fn to_bytes(&self) -> Vec<Byte>;

    /// Convert this value into an [`Arg`] for calling with a function.
    /// This allows parasol to understand how to pass arguments to a program.
    ///
    /// See [here](https://drive.google.com/file/d/1Ja_Tpp_5Me583CGVD-BIZMlgGBnlKU4R/view?pli=1) for
    /// details.
    ///
    /// # Panics
    /// If `self.to_bytes().len() != self.size()`.
    fn to_arg(&self) -> Arg {
        let bytes = self.to_bytes();

        assert_eq!(bytes.len(), self.size());

        Arg {
            alignment: self.alignment(),
            bytes,
        }
    }

    /// Attempt to create a value of this type from the given bytes.
    fn try_from_bytes(data: Vec<Byte>) -> Result<Self>;
}

macro_rules! primitive_impl_to_arg {
    ($t:ty) => {
        paste! {
            impl ToArg for $t {
                fn alignment() -> usize {
                    std::mem::align_of::<$t>()
                }

                fn size() -> usize {
                    std::mem::size_of::<$t>()
                }

                fn to_bytes(&self) -> Vec<Byte> {
                    self.to_le_bytes().map(|x| Byte::from(x)).into_iter().collect::<Vec<_>>()
                }

                fn try_from_bytes(data: Vec<Byte>) -> Result<Self> {
                    let mut val: $t = 0;

                    if data.len() != Self::size() {
                        return Err(Error::TypeSizeMismatch);
                    }

                    for (i, b) in data.into_iter().enumerate() {
                        match b {
                            Byte::Plaintext(b) => { val |= (b as $t) << (8 * i) },
                            Byte::Ciphertext(_) => return Err(Error::EncryptionMismatch),
                        }
                    }

                    Ok(val)
                }
            }

            #[cfg(test)]
            mod [<test_ $t:lower>] {
                use super::*;

                #[test]
                fn [<test_to_args_ $t:lower>]() {
                    let x = $t::default();
                    let args = x.to_arg();

                    assert_eq!(args.bytes.len(), std::mem::size_of::<$t>());
                }

                #[test]
                fn [<try_from_bytes_ $t:lower>]() {
                    let bytes: [u8; std::mem::size_of::<$t>()] = std::array::from_fn(|x| x as u8);
                    let expected = $t::from_le_bytes(bytes);
                    let bytes = bytes.into_iter().map(|x| Byte::from(x)).collect::<Vec<_>>();

                    let actual = $t::try_from_bytes(bytes).unwrap();

                    assert_eq!(actual, expected);
                }
            }

        }
    };
}

primitive_impl_to_arg!(u8);
primitive_impl_to_arg!(u16);
primitive_impl_to_arg!(u32);
primitive_impl_to_arg!(u64);
primitive_impl_to_arg!(u128);
primitive_impl_to_arg!(i8);
primitive_impl_to_arg!(i16);
primitive_impl_to_arg!(i32);
primitive_impl_to_arg!(i64);
primitive_impl_to_arg!(i128);

impl<const N: usize> ToArg for UInt<N, L1GlweCiphertext> {
    fn alignment() -> usize {
        N / 8
    }

    fn size() -> usize {
        N / 8
    }

    fn to_bytes(&self) -> Vec<Byte> {
        assert!(N.is_power_of_two() && N % 8 == 0);

        self.bits
            .chunks(8)
            .map(|x| Byte::try_from(x.to_owned()).unwrap())
            .collect()
    }

    fn try_from_bytes(data: Vec<Byte>) -> Result<Self> {
        if data.len() != N / 8 {
            return Err(Error::TypeSizeMismatch);
        }

        let data = data
            .into_iter()
            .map(|x| match x {
                Byte::Plaintext(_) => Err(Error::EncryptionMismatch),
                Byte::Ciphertext(val) => Ok(val),
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        Ok(UInt::from_bits_shallow(data))
    }
}

impl<const N: usize> ToArg for Int<N, L1GlweCiphertext> {
    fn alignment() -> usize {
        N / 8
    }

    fn size() -> usize {
        N / 8
    }

    fn to_bytes(&self) -> Vec<Byte> {
        assert!(N.is_power_of_two() && N % 8 == 0);

        self.bits
            .chunks(8)
            .map(|x| Byte::try_from(x.to_owned()).unwrap())
            .collect()
    }

    fn try_from_bytes(data: Vec<Byte>) -> Result<Self> {
        if data.len() != N / 8 {
            return Err(Error::TypeSizeMismatch);
        }

        let data = data
            .into_iter()
            .map(|x| match x {
                Byte::Plaintext(_) => Err(Error::EncryptionMismatch),
                Byte::Ciphertext(val) => Ok(val),
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        Ok(Int::from_bits_shallow(data))
    }
}

impl<const N: usize, T: ToArg> ToArg for [T; N] {
    fn alignment() -> usize {
        T::alignment()
    }

    fn size() -> usize {
        T::size().next_multiple_of(T::alignment()) * N
    }

    fn to_bytes(&self) -> Vec<Byte> {
        if T::size() == 0 {
            return vec![];
        }

        self.iter()
            .flat_map(|x| {
                // Pad each array element to its alignment...
                let bytes = x.to_bytes();

                bytes
                    .iter()
                    .chain(std::iter::repeat(&bytes[0]))
                    .take(T::size().next_multiple_of(T::alignment()))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    }

    fn try_from_bytes(data: Vec<Byte>) -> Result<Self> {
        // ZSTs are zesty and need to ignore the normal padding rules.
        if T::size() == 0 {
            if !data.is_empty() {
                return Err(Error::TypeSizeMismatch);
            }

            let as_vec = std::array::from_fn::<_, N, _>(|_| T::try_from_bytes(vec![]))
                .into_iter()
                .collect::<Result<Vec<_>>>()?
                .try_into();

            return Ok(as_vec.unwrap_or_else(|_| unreachable!()));
        }

        let as_vec = data
            // Strip off the padding and recreate the Ts
            .chunks(T::size().next_multiple_of(T::alignment()))
            .map(|x| T::try_from_bytes(x.to_owned()))
            .collect::<Result<Vec<_>>>()?;

        if as_vec.len() != N {
            return Err(Error::TypeSizeMismatch);
        }

        Ok(as_vec.try_into().unwrap_or_else(|_| unreachable!()))
    }
}

impl ToArg for () {
    fn alignment() -> usize {
        1
    }

    fn size() -> usize {
        0
    }

    fn to_bytes(&self) -> Vec<Byte> {
        vec![]
    }

    fn try_from_bytes(data: Vec<Byte>) -> Result<Self> {
        if !data.is_empty() {
            return Err(Error::TypeSizeMismatch);
        }

        Ok(())
    }
}

impl DynamicToArg for DynamicUInt<L1GlweCiphertext> {
    fn alignment(&self) -> usize {
        self.bits.len() / 8
    }

    fn size(&self) -> usize {
        self.bits.len() / 8
    }

    fn is_signed() -> bool {
        false
    }

    fn to_bytes(&self) -> Vec<Byte> {
        assert!(self.bits.len().is_power_of_two() && self.bits.len() % 8 == 0);

        self.bits
            .chunks(8)
            .map(|x| Byte::try_from(x.to_owned()).unwrap())
            .collect()
    }

    fn try_from_bytes(data: Vec<Byte>) -> Result<Self> {
        let data = data
            .into_iter()
            .map(|x| match x {
                Byte::Plaintext(_) => Err(Error::EncryptionMismatch),
                Byte::Ciphertext(val) => Ok(val),
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        Ok(DynamicUInt::from_bits_shallow(data))
    }
}

impl DynamicToArg for DynamicInt<L1GlweCiphertext> {
    fn alignment(&self) -> usize {
        self.bits.len() / 8
    }

    fn size(&self) -> usize {
        self.bits.len() / 8
    }

    fn is_signed() -> bool {
        true
    }

    fn to_bytes(&self) -> Vec<Byte> {
        assert!(self.bits.len().is_power_of_two() && self.bits.len() % 8 == 0);

        self.bits
            .chunks(8)
            .map(|x| Byte::try_from(x.to_owned()).unwrap())
            .collect()
    }

    fn try_from_bytes(data: Vec<Byte>) -> Result<Self> {
        let data = data
            .into_iter()
            .map(|x| match x {
                Byte::Plaintext(_) => Err(Error::EncryptionMismatch),
                Byte::Ciphertext(val) => Ok(val),
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        Ok(DynamicInt::from_bits_shallow(data))
    }
}

/// A type for passing arguments to Parasol programs. When invoking
/// [`crate::FheComputer::run_program`], the processor will transparently set up the registers
/// and first stack frame according to Parasol ABI's calling convention.
///
/// # Remarks
/// Parasol's calling convention is similar to x86's cdecl. We first allocate stack space for
/// storing all arguments and the return value as well as padding to maintain alignment
/// requirements for each argument and the return value. Furthermore, the stack pointer must be
/// 16-byte aligned after pushing all the call data. Arguments are stored in reverse order
/// (i.e. the first argument appears at SP+0 while the second at SP+sizeof(arg1), and so-on),
/// followed by the return value.
///
/// Parasol stacks grow downwards, while arguments and values within a frame grow upwards.
pub struct ArgsBuilder {
    args: Vec<Arg>,
}

impl Default for ArgsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ArgsBuilder {
    /// Create a new [`ArgsBuilder`].
    pub fn new() -> Self {
        Self { args: vec![] }
    }

    /// Add an argument
    pub fn arg<T: ToArg>(mut self, val: T) -> Self {
        self.args.push(val.to_arg());

        self
    }

    /// Similar to [`ArgsBuilder::arg`] but the value is [`DynamicToArg`]
    pub fn arg_dyn<T: DynamicToArg>(mut self, val: T) -> Self {
        self.args.push(val.to_arg());

        self
    }

    /// Specify a return value for an FHE program.
    ///
    /// # Remarks
    /// If an FHE program returns a value greater than 8 bytes, you must specify this, even if you
    /// don't use it.
    /// Failure to do so will result in incorrect execution.
    pub fn return_value<T: ToArg>(self) -> CallData<T> {
        CallData {
            args: self.args,
            return_value: T::to_return_value(),
        }
    }

    /// Specify a generic return value type for an FHE program
    pub fn return_value_raw(self, align: usize, num_bytes: usize) -> CallData<Vec<Byte>> {
        CallData {
            args: self.args,
            return_value: ReturnValue {
                alignment: align,
                size: num_bytes,
                _phantom: PhantomData,
            },
        }
    }

    /// Create the [`CallData`] object from this builder, ignoring any value the program returns (if any).
    pub fn no_return_value(self) -> CallData<()> {
        self.return_value::<()>()
    }
}

/// The info needed to pass an argument to a function from the host program.
pub struct Arg {
    /// The alignment of the argument.
    pub alignment: usize,

    /// The bytes of the argument.
    pub bytes: Vec<Byte>,
}

/// The info needed to capture the return value from an FHE program on the host.
pub struct ReturnValue<T> {
    /// The alignment requirement of the return value.
    pub alignment: usize,

    /// The number of bytes needed to store the return value.
    pub size: usize,

    _phantom: PhantomData<T>,
}

/// Arguments passed to an FHE program when calling [`crate::FheComputer::run_program`].
pub struct CallData<T> {
    pub(crate) return_value: ReturnValue<T>,
    pub(crate) args: Vec<Arg>,
}

impl<T> CallData<T> {
    /// Returns the required size for this call data, including aligning the stack pointer
    /// to a 16-byte boundary
    pub fn alloc_size(&self) -> usize {
        let mut ptr = 0;

        for arg in self.args.iter() {
            // Account for this argument's alignment
            ptr += (arg.alignment - ptr % arg.alignment) % arg.alignment;
            ptr += arg.bytes.len();
        }

        if self.return_value.size > 0 {
            ptr += (self.return_value.alignment - ptr % self.return_value.alignment)
                % self.return_value.alignment;
            ptr += self.return_value.size;
        }

        ptr += (16 - ptr % 16) % 16;

        ptr
    }
}

#[cfg(test)]
mod tests {
    use super::ToArg;

    #[test]
    fn can_roundtrip_array() {
        let values = std::array::from_fn::<_, 16, _>(|i| i as u32);

        let bytes = values.to_bytes();
        let actual = <[u32; 16]>::try_from_bytes(bytes).unwrap();

        assert_eq!(values, actual);
    }
}
