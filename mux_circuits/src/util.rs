use crate::{error::Error, graph_ops::Bit};

// From nightly, originally is a macro that worked over all unsigned integer
// sizes.
/// Calculates `lhs` &minus; `rhs` &minus; `borrow` and returns a tuple
/// containing the difference and the output borrow.
///
/// Performs "ternary subtraction" by subtracting both an integer
/// operand and a borrow-in bit from `lhs`, and returns an output
/// integer and a borrow-out bit. This allows chaining together multiple
/// subtractions to create a wider subtraction, and can be useful for
/// bignum subtraction.
pub fn borrowing_sub(lhs: u128, rhs: u128, borrow: bool) -> (u128, bool) {
    let (a, b) = lhs.overflowing_sub(rhs);
    let (c, d) = a.overflowing_sub(borrow as u128);
    (c, b || d)
}

/// Calculates `lhs` &minus; `rhs` &minus; `borrow` and returns a tuple
/// containing the difference and the output borrow. This is the same as
/// [borrowing_sub] but where any bit width up to 128 bits can be used.
///
/// Performs "ternary subtraction" by subtracting both an integer
/// operand and a borrow-in bit from `lhs`, and returns an output
/// integer and a borrow-out bit. This allows chaining together multiple
/// subtractions to create a wider subtraction, and can be useful for
/// bignum subtraction.
pub fn arbitrary_width_borrowing_sub(
    lhs: u128,
    rhs: u128,
    borrow: u128,
    width: u32,
) -> (u128, u128) {
    let diff_mask = (0x1 << width) - 1;

    let (diff, borrow) = borrowing_sub(lhs, rhs, borrow != 0);

    let diff = diff & diff_mask;

    (diff, borrow as u128)
}

/// Convenience function during testing that decomposes the given `val` into a `bits`-bit integer.
///
/// # Remarks
/// The bits are returned from least to most significant order.
pub fn try_to_bits(val: u64, bits: usize) -> Result<Vec<Bit>, Error> {
    let mut result = vec![Bit(false); bits];

    if val >= 0x1 << bits {
        return Err(Error::OutOfRange);
    }

    for (i, result) in result
        .iter_mut()
        .enumerate()
        .take(usize::min(bits, u64::BITS as usize))
    {
        *result = Bit((val >> i) & 0x1 == 1);
    }

    Ok(result)
}
