use std::marker::PhantomData;

use crate::Byte;
use crate::{Error, Result};
use parasol_runtime::fluent::Bool;
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

impl ToArg for bool {
    fn alignment() -> usize {
        1
    }

    fn size() -> usize {
        1
    }

    fn to_bytes(&self) -> Vec<Byte> {
        vec![Byte::from(if *self { 0x01u8 } else { 0u8 })]
    }

    fn try_from_bytes(data: Vec<Byte>) -> Result<Self> {
        if data.len() != 1 {
            return Err(Error::TypeSizeMismatch);
        }

        match &data[0] {
            Byte::Plaintext(val) => Ok(*val != 0),
            _ => Err(Error::TypeSizeMismatch),
        }
    }
}

impl<const N: usize> ToArg for UInt<N, L1GlweCiphertext> {
    fn alignment() -> usize {
        N / 8
    }

    fn size() -> usize {
        N / 8
    }

    fn to_bytes(&self) -> Vec<Byte> {
        assert!(N.is_power_of_two() && N.is_multiple_of(8));

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
        assert!(N.is_power_of_two() && N.is_multiple_of(8));

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

impl ToArg for Bool {
    fn alignment() -> usize {
        1
    }

    fn size() -> usize {
        1
    }

    fn to_bytes(&self) -> Vec<Byte> {
        // With ZeroOrOneBooleanContent, all other bits should be zero
        let trivial_zero = self.trivial_zero_from_existing();
        let mut bits = Vec::with_capacity(8);
        bits.push(self.inner().clone());
        for _ in 0..7 {
            bits.push(trivial_zero.inner().clone());
        }

        let uint8 = UInt::<8, L1GlweCiphertext>::from_bits_shallow(bits);
        uint8.to_bytes()
    }

    fn try_from_bytes(data: Vec<Byte>) -> Result<Self> {
        if data.len() != 1 {
            return Err(Error::TypeSizeMismatch);
        }

        let uint8 = UInt::<8, L1GlweCiphertext>::try_from_bytes(data)?;

        if uint8.bits.is_empty() {
            return Err(Error::TypeSizeMismatch);
        }

        Ok(Bool::from(uint8.bits[0].clone()))
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

    fn to_bytes(&self) -> Vec<Byte> {
        assert!(self.bits.len().is_power_of_two() && self.bits.len().is_multiple_of(8));

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

    fn to_bytes(&self) -> Vec<Byte> {
        assert!(self.bits.len().is_power_of_two() && self.bits.len().is_multiple_of(8));

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

// This implementation is essentially the same as the array ToArg
// implementation, but without the casting to an array.
impl<T: ToArg> DynamicToArg for Vec<T> {
    fn alignment(&self) -> usize {
        T::alignment()
    }

    fn size(&self) -> usize {
        if T::size() == 0 {
            return 0;
        }

        T::size().next_multiple_of(T::alignment()) * self.len()
    }

    fn to_bytes(&self) -> Vec<Byte> {
        if T::size() == 0 {
            return vec![];
        }

        self.iter()
            .flat_map(|x| {
                // Pad each vector element to its alignment (same pattern as arrays)
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

            let as_vec = (0..data.len())
                .map(|_| T::try_from_bytes(vec![]))
                .collect::<Result<Vec<_>>>()?;

            return Ok(as_vec);
        }

        let as_vec = data
            // Strip off the padding and recreate the Ts
            .chunks(T::size().next_multiple_of(T::alignment()))
            .map(|x| T::try_from_bytes(x.to_owned()))
            .collect::<Result<Vec<_>>>()?;

        Ok(as_vec)
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
    pub fn return_value<T: ToArg>(self) -> CallData<T> {
        CallData {
            args: self.args,
            return_value: T::to_return_value(),
        }
    }

    /// Specify a return value for an FHE program using the alignment and size.
    pub fn return_value_dyn(self, align: usize, num_bytes: usize) -> CallData<Vec<Byte>> {
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
#[derive(Clone)]
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
        let mut offset = 0usize;

        for arg in self.args.iter() {
            // Account for this argument's alignment
            offset = offset.next_multiple_of(arg.alignment);
            offset += arg.bytes.len();
        }

        // Allocate space for our return value.
        if self.return_value.size > 0 {
            // Account for our return value's alignment
            offset = offset.next_multiple_of(self.return_value.alignment);
            offset += self.return_value.size;
        }

        // Finally, align the stack to the next 16-byte boundary
        offset = offset.next_multiple_of(16);

        offset
    }

    pub(crate) fn to_dyn(&self) -> CallData<Vec<Byte>> {
        CallData {
            return_value: ReturnValue {
                alignment: self.return_value.alignment,
                size: self.return_value.size,
                _phantom: PhantomData,
            },
            args: self.args.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Bool, DynamicToArg, ToArg};
    use parasol_runtime::{
        L1GlweCiphertext,
        fluent::UInt,
        test_utils::{get_encryption_128, get_secret_keys_128},
    };

    #[test]
    fn can_roundtrip_array() {
        let values = std::array::from_fn::<_, 16, _>(|i| i as u32);

        let bytes = values.to_bytes();
        let actual = <[u32; 16]>::try_from_bytes(bytes).unwrap();

        assert_eq!(values, actual);
    }

    #[test]
    fn can_roundtrip_vec_u32() {
        let values: Vec<u32> = (0..10).collect();

        let bytes = values.to_bytes();
        let actual = Vec::<u32>::try_from_bytes(bytes).unwrap();

        assert_eq!(values, actual);
    }

    #[test]
    fn can_roundtrip_vec_different_types() {
        let values_u8: Vec<u8> = vec![1, 2, 3, 4, 5];
        let bytes = values_u8.to_bytes();
        let actual = Vec::<u8>::try_from_bytes(bytes).unwrap();
        assert_eq!(values_u8, actual);

        let values_u16: Vec<u16> = vec![100, 200, 300];
        let bytes = values_u16.to_bytes();
        let actual = Vec::<u16>::try_from_bytes(bytes).unwrap();
        assert_eq!(values_u16, actual);

        let values_u64: Vec<u64> = vec![1000, 2000];
        let bytes = values_u64.to_bytes();
        let actual = Vec::<u64>::try_from_bytes(bytes).unwrap();
        assert_eq!(values_u64, actual);
    }

    #[test]
    fn can_handle_empty_vec() {
        let empty_vec: Vec<u32> = vec![];

        let bytes = empty_vec.to_bytes();
        assert_eq!(bytes.len(), 0);

        let actual = Vec::<u32>::try_from_bytes(bytes).unwrap();
        assert_eq!(empty_vec, actual);
    }

    #[test]
    fn can_handle_vec_zst() {
        let zst_vec: Vec<()> = vec![(), (), ()];

        let bytes = zst_vec.to_bytes();
        assert_eq!(bytes.len(), 0);

        // Note: For ZSTs, we can't recover the original length, so we get empty vec
        let actual = Vec::<()>::try_from_bytes(bytes).unwrap();
        assert_eq!(actual.len(), 0);
    }

    #[test]
    fn vec_alignment_and_size_calculations() {
        let vec_u8: Vec<u8> = vec![1, 2, 3];
        assert_eq!(vec_u8.alignment(), 1);
        assert_eq!(vec_u8.size(), 3); // u8 size=1, alignment=1, no padding needed

        let vec_u32: Vec<u32> = vec![1, 2];
        assert_eq!(vec_u32.alignment(), 4);
        assert_eq!(vec_u32.size(), 8); // u32 size=4, alignment=4, 2 elements

        let empty_vec: Vec<u32> = vec![];
        assert_eq!(empty_vec.alignment(), 4);
        assert_eq!(empty_vec.size(), 0);
    }

    #[test]
    fn vec_byte_layout_matches_array() {
        // Vec<T> should have the same byte layout as [T; N] for same elements
        let vec_values: Vec<u32> = vec![0x12345678, 0x9ABCDEF0];
        let array_values = [0x12345678u32, 0x9ABCDEF0u32];

        let vec_bytes = vec_values.to_bytes();
        let array_bytes = array_values.to_bytes();

        // Compare byte by byte since Byte doesn't implement PartialEq
        assert_eq!(vec_bytes.len(), array_bytes.len());
        for (vec_byte, array_byte) in vec_bytes.iter().zip(array_bytes.iter()) {
            match (vec_byte, array_byte) {
                (crate::Byte::Plaintext(a), crate::Byte::Plaintext(b)) => assert_eq!(a, b),
                _ => panic!("Expected plaintext bytes"),
            }
        }
    }

    #[test]
    fn can_roundtrip_vec_encrypted() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();

        // Create a vector of encrypted values
        let plaintext_values = [10u128, 20u128, 30u128];
        let encrypted_vec: Vec<UInt<32, L1GlweCiphertext>> = plaintext_values
            .iter()
            .map(|&val| UInt::encrypt_secret(val, &enc, &sk))
            .collect();

        let bytes = encrypted_vec.to_bytes();
        let recovered: Vec<UInt<32, L1GlweCiphertext>> = Vec::try_from_bytes(bytes).unwrap();

        // Verify the encrypted values decrypt correctly
        for (original, recovered) in encrypted_vec.iter().zip(recovered.iter()) {
            assert_eq!(original.decrypt(&enc, &sk), recovered.decrypt(&enc, &sk));
        }
    }

    #[test]
    fn vec_padding_behavior() {
        // Test that padding works correctly for types with different alignments

        // u8 has no padding (alignment = 1)
        let vec_u8: Vec<u8> = vec![1, 2, 3];
        assert_eq!(vec_u8.size(), 3);

        // u16 has alignment = 2, but since size = 2, no extra padding needed
        let vec_u16: Vec<u16> = vec![1, 2, 3];
        assert_eq!(vec_u16.size(), 6); // 3 * 2
    }

    #[test]
    fn vec_error_handling() {
        // Test size mismatch error
        let malformed_data = vec![
            crate::Byte::from(1u8),
            crate::Byte::from(2u8),
            crate::Byte::from(3u8),
        ];

        // Trying to deserialize 3 bytes as Vec<u32> should fail (u32 needs 4 bytes per element)
        let result = Vec::<u32>::try_from_bytes(malformed_data);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::Error::TypeSizeMismatch
        ));
    }

    #[test]
    fn can_roundtrip_bool() {
        let true_value = true;
        let false_value = false;

        let true_bytes = true_value.to_bytes();
        let false_bytes = false_value.to_bytes();

        assert_eq!(true_bytes.len(), 1);
        assert_eq!(false_bytes.len(), 1);

        let recovered_true = bool::try_from_bytes(true_bytes).unwrap();
        let recovered_false = bool::try_from_bytes(false_bytes).unwrap();

        assert!(recovered_true);
        assert!(!recovered_false);
    }

    #[test]
    fn bool_alignment_and_size() {
        assert_eq!(bool::alignment(), 1);
        assert_eq!(bool::size(), 1);
    }

    #[test]
    fn bool_byte_representation() {
        let true_bytes = true.to_bytes();
        let false_bytes = false.to_bytes();

        match &true_bytes[0] {
            crate::Byte::Plaintext(val) => assert_eq!(*val, 0x01),
            _ => panic!("Expected plaintext byte"),
        }

        match &false_bytes[0] {
            crate::Byte::Plaintext(val) => assert_eq!(*val, 0),
            _ => panic!("Expected plaintext byte"),
        }
    }

    #[test]
    fn bool_cannot_recover_from_incorrect_size() {
        // Test wrong size
        let wrong_size_data = vec![crate::Byte::from(1u8), crate::Byte::from(2u8)];
        let result = bool::try_from_bytes(wrong_size_data);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::Error::TypeSizeMismatch
        ));
    }

    #[test]
    fn bool_cannot_recover_from_encrypted_data() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();
        let encrypted_bool = Bool::encrypt_secret(true, &enc, &sk);
        let encrypted_data = encrypted_bool.to_bytes();
        let result = bool::try_from_bytes(encrypted_data);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::Error::TypeSizeMismatch
        ));
    }

    #[test]
    fn can_roundtrip_bool_encrypted() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();

        let true_value = Bool::encrypt_secret(true, &enc, &sk);
        let false_value = Bool::encrypt_secret(false, &enc, &sk);

        let true_bytes = true_value.to_bytes();
        let false_bytes = false_value.to_bytes();

        assert_eq!(true_bytes.len(), 1);
        assert_eq!(false_bytes.len(), 1);

        let recovered_true = Bool::try_from_bytes(true_bytes).unwrap();
        let recovered_false = Bool::try_from_bytes(false_bytes).unwrap();

        assert!(recovered_true.decrypt(&enc, &sk));
        assert!(!recovered_false.decrypt(&enc, &sk));
    }

    #[test]
    fn bool_encrypted_alignment_and_size() {
        assert_eq!(Bool::alignment(), 1);
        assert_eq!(Bool::size(), 1);
    }

    #[test]
    fn bool_encrypted_cannot_recover_from_incorrect_size() {
        let wrong_size_data = vec![crate::Byte::from(1u8), crate::Byte::from(2u8)];
        let result = Bool::try_from_bytes(wrong_size_data);
        assert!(result.is_err());
        match result {
            Err(crate::Error::TypeSizeMismatch) => {}
            _ => panic!("Expected TypeSizeMismatch error"),
        }
    }

    #[test]
    fn bool_encrypted_cannot_recover_from_plaintext() {
        let plaintext_data = vec![crate::Byte::from(1u8)];
        let result = Bool::try_from_bytes(plaintext_data);
        assert!(result.is_err());
        match result {
            Err(crate::Error::EncryptionMismatch) => {}
            Err(crate::Error::TypeSizeMismatch) => {}
            _ => panic!("Expected EncryptionMismatch or TypeSizeMismatch error"),
        }
    }
}
