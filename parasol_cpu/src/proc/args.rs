use std::marker::PhantomData;

use crate::{Byte, Ptr32};
use crate::{Error, Result};
use parasol_runtime::{
    L1GlweCiphertext,
    fluent::{Int, UInt},
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

    /// Whether this type needs to be sign extended or not.
    fn is_signed() -> bool;

    /// Convert a byte array and metadata into an [`Arg`] indicating the alignment,
    /// size, and how to extend the given value.
    fn bytes_to_arg(bytes: Vec<Byte>, is_signed: bool) -> Arg {
        Arg {
            alignment: Self::alignment(),
            is_signed,
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

        Self::bytes_to_arg(bytes, Self::is_signed())
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

macro_rules! primitive_impl_to_arg {
    ($t:ty,$signed:literal) => {
        paste! {
            impl ToArg for $t {
                fn alignment() -> usize {
                    std::mem::align_of::<$t>()
                }

                fn size() -> usize {
                    std::mem::size_of::<$t>()
                }

                fn is_signed() -> bool {
                    $signed
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

primitive_impl_to_arg!(u8, false);
primitive_impl_to_arg!(u16, false);
primitive_impl_to_arg!(u32, false);
primitive_impl_to_arg!(u64, false);
primitive_impl_to_arg!(u128, false);
primitive_impl_to_arg!(i8, true);
primitive_impl_to_arg!(i16, true);
primitive_impl_to_arg!(i32, true);
primitive_impl_to_arg!(i64, true);
primitive_impl_to_arg!(i128, true);

impl<const N: usize> ToArg for UInt<N, L1GlweCiphertext> {
    fn alignment() -> usize {
        return N / 8;
    }

    fn size() -> usize {
        return N / 8;
    }

    fn is_signed() -> bool {
        false
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
        return N / 8;
    }

    fn size() -> usize {
        return N / 8;
    }

    fn is_signed() -> bool {
        true
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
        return T::alignment();
    }

    fn size() -> usize {
        return T::size().next_multiple_of(T::alignment()) * N;
    }

    fn is_signed() -> bool {
        false
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

    fn is_signed() -> bool {
        false
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

/// A type for passing arguments to Parasol programs. When invoking
/// [`crate::FheComputer::run_program`], the processor will transparently set up the registers
/// and first stack frame according to Parasol ABI's calling convention.
///
/// # Remarks
/// Parasol follows the ILP32 RISC-V [calling convention](https://drive.google.com/file/d/1Ja_Tpp_5Me583CGVD-BIZMlgGBnlKU4R/view?pli=1).
///
/// 4-byte or smaller scalars go in the next available a0-a7 register. Smaller signed/unsigned
///  scalars are sign/zero extended to 32-bit (respectively). If no registers remain, they get
/// pushed on the stack. In this case, values are aligned, but not sign extended.
///
/// 5-8 byte scalars go in the next 2 available registers. The lo word
/// goes into the first and the high word into the second. Signed/unsigned scalars are
/// sign/zero extended to 32-bits (respectively). If one register remains, the lo word goes into the
/// register while the high word goes on the stack. If no registers remain, they both get pushed onto
/// the stack, where they will be aligned but not extended.
///
/// 1-4 byte aggregates get packed into a single register (if available) or placed
/// on the stack according to its alignment requirements.
///
/// 5-8 byte aggregate values get packed into 2 registers (if available). If
/// only one register is available, the lo 32-bits go in the register while the high
/// bits go on the stack. If no registers are available, both words get pushed on
/// the stack.
///
/// Scalars or aggregates larger than 64-bits will be transparently allocated on the
/// Parasol heap and passed by reference (i.e. a 32-bit pointer will be passed for the corresponding
/// register/stack argument).
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

    /// Specify a return value for an FHE program.
    ///
    /// # Remarks
    /// If an FHE program returns a value greater than 8 bytes, you must specify this, even if you
    /// don't use it.
    /// Failure to do so will result in incorrect execution.
    pub fn return_value<T: ToArg>(self) -> Args<T> {
        Args {
            args: self.args,
            return_value: T::to_return_value(),
        }
    }

    /// Create the [`Args`] object from this builder, ignoring any value the program returns (if any).
    pub fn no_return_value(self) -> Args<()> {
        self.return_value::<()>()
    }
}

/// The info needed to pass an argument to a function from the host program.
pub struct Arg {
    /// The alignment of the argument.
    pub alignment: usize,

    /// Whether the argument should be sign extended or not.
    pub is_signed: bool,

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
pub struct Args<T> {
    pub(crate) return_value: ReturnValue<T>,
    pub(crate) args: Vec<Arg>,
}

impl<T> Args<T> {
    /// Return the number of padding bytes that need to be allocated to align the
    /// stack to the required 16-byte boundary.
    ///
    /// # Remarks
    /// In accordance with RISC-V ILP32 calling convention.
    pub fn stack_padding(&self) -> u32 {
        let mut stack_size = 0usize;
        let mut free_regs = 8;

        // TODO: I don't think the math is quite right for aggregate types.
        // In particular, consider `struct { char a; short b; char c; };`.
        // If we're already using 7 registers, then a, b can appear in x17,
        // then c spills onto the stack taking only 1 byte. If the next argument
        // is a char, it should immediately get placed on the stack with no padding.
        for a in self.args.iter() {
            match a.bytes.len() {
                0 => {} // ZSTs are never actually manifested.
                1..=4 => {
                    // 1-4 byte values pack into a register. Failing that, they get written
                    // to the stack.
                    if free_regs > 0 {
                        free_regs -= 1;
                    } else {
                        stack_size = stack_size.next_multiple_of(a.alignment);
                        stack_size += a.bytes.len();
                    }
                }
                5..=8 => {
                    // 5-8 byte values get passed in 2 registers, overflowing any excess onto the
                    // stack
                    if free_regs > 1 {
                        free_regs -= 2;
                    } else if free_regs > 0 {
                        // If 1 register is available, the upper 5-8 bytes get written to the
                        // stack.
                        stack_size = stack_size.next_multiple_of(4);
                        stack_size += a.bytes.len() - 4;
                        free_regs -= 1;
                    } else {
                        stack_size = stack_size.next_multiple_of(a.alignment);
                        stack_size += a.bytes.len();
                    }
                }
                _ => {
                    // > 8 byte values are allocated by the caller and passed by reference.
                    // Thus, each of these arguments requires 4-bytes for the pointer.
                    if free_regs > 1 {
                        free_regs -= 1;
                    } else {
                        stack_size = stack_size.next_multiple_of(Ptr32::alignment());
                        stack_size += Ptr32::size();
                    }
                }
            }
        }

        (stack_size.next_multiple_of(16) - stack_size) as u32
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
