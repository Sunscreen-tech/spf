use std::{collections::HashSet, fmt::Display};

use biodivine_lib_bdd::{Bdd, BddVariableSet};

use crate::MuxCircuit;

use sunscreen_math::combination::Combinations;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
/// Parameters that define an `n`-by-`m` multiplier circuit.
pub struct MultiplierParams {
    /// `n`
    pub n: usize,

    /// `m`
    pub m: usize,
}

impl Display for MultiplierParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({},{})", self.n, self.m)
    }
}

/// Create an nxm multiplier circuit.
///
/// # Remarks
/// The inputs should be ordered from LSB to MSB and interleaved between operands a and b.
/// When m doesn't equal m, the excess bits from a or b will appear at the end.
pub fn multiplier_impl(params: MultiplierParams) -> MuxCircuit {
    let MultiplierParams { n, m } = params;

    assert!(n > 0);
    assert!(m > 0);
    assert!(m + n < (0x1 << 16));

    let bdd = multiplier_bdd(n, m);

    // The resulting mux tree duplicates inputs many times to make a more efficient
    // circuit. We'll want to convert the circuit into one that accepts n + m inputs.
    let mut mux_circuit = MuxCircuit::from(bdd.as_slice());

    let n = n as u32;
    let m = m as u32;

    // Having constructed our mux_circuit, we now want to remap all of our inputs.
    // in the encoded BDD input, each x index appears at an odd value and each
    // y index is even. Use this fact to deduplicate input nodes.
    mux_circuit.remap_inputs(m + n, || {
        let x_inputs = (0..n).collect::<Vec<_>>();
        let y_inputs = (n..n + m).collect::<Vec<_>>();

        mul_bdd_encode(&x_inputs, &y_inputs)
    });

    mux_circuit.optimize();

    mux_circuit
}

/// Create an `n`-by-`m` unsigned multiplier circuit.
pub fn unsigned_multiplier(n: usize, m: usize) -> MuxCircuit {
    match (n, m) {
        (8, 8) => bincode::deserialize(include_bytes!("data/multiplier-n8-m8")).unwrap(),
        (16, 16) => bincode::deserialize(include_bytes!("data/multiplier-n16-m16")).unwrap(),
        (32, 32) => bincode::deserialize(include_bytes!("data/multiplier-n32-m32")).unwrap(),
        _ => multiplier_impl(MultiplierParams { n, m }),
    }
}

/// Constructions a BDD-based n x m -> (n + m)-bit multiplier.
///
/// # Remarks
/// For a description of this circuit, see "Using BDDs to Verify Multipliers" by
/// Jerry R. Burch. A picture exists on page 4.
fn multiplier_bdd(n: usize, m: usize) -> Vec<Bdd> {
    let variable_set = BddVariableSet::new_anonymous((2 * n * m) as u16);
    let vars = variable_set.variables();
    let vars = vars
        .iter()
        .map(|v| variable_set.mk_var(*v))
        .collect::<Vec<_>>();

    // Reorder the variables
    let (x, y) = mul_bdd_decode(&vars, n, m);

    let idx = |row, col| row * n + col;

    let ands = x
        .iter()
        .zip(y.iter())
        .map(|(x, y)| x.and(y))
        .collect::<Vec<_>>();
    let mut sums = vec![variable_set.mk_false(); m * n];
    let mut carries = vec![variable_set.mk_false(); m * n];

    for i in 0..n {
        sums[i] = ands[idx(0, i)].clone();
    }

    for i in 1..m {
        for j in 0..n {
            let a = &ands[idx(i, j)];

            // The first n - 1 columns should use the sum of the j + 1 column of
            // the previous row.
            // The last column should take the carry out from the previous row's final
            // column (which will be 0 for the first row).
            let b = if j < n - 1 {
                sums[idx(i - 1, j + 1)].clone()
            } else {
                carries[idx(i - 1, j)].clone()
            };

            // Each column should carry in the carry from the previous column. For the
            // first column, we will have no carry.
            let c_in = if j > 0 {
                carries[idx(i, j - 1)].clone()
            } else {
                variable_set.mk_false()
            };

            let a_xor_b = a.xor(&b);
            sums[idx(i, j)] = a_xor_b.xor(&c_in);
            carries[idx(i, j)] = a_xor_b.and(&c_in).or(&b.and(a));
        }
    }

    let mut result = vec![];

    for i in 0..m {
        result.push(sums[idx(i, 0)].clone());
    }

    for i in 1..n {
        result.push(sums[idx(m - 1, i)].clone());
    }

    result.push(carries[idx(m - 1, n - 1)].clone());

    result
}

/// Values x and y are given in little-endian. Encode them for use in `x.len() x y.len()` multiplier.
///
/// # Remarks
/// The encoding and input repetition technique is described in "Using BDDs to Verify
/// Multipliers." This is the efficient high-to-low ordering, which results in O(n^3)
/// Mux trees.
fn mul_bdd_encode<T: Copy>(x: &[T], y: &[T]) -> Vec<T> {
    assert_ne!(x.len(), 0);
    assert_ne!(y.len(), 0);

    let mut encoded = vec![];
    let n = x.len();
    let m = y.len();

    let num_diags = n + m - 1;

    for d in (1..=num_diags).rev() {
        let (row, col) = if d > n { (d - n, 0) } else { (0, n - d) };

        let mut i = 0;
        loop {
            let r = row + i;
            let c = col + i;

            if r >= m || c >= n {
                break;
            }

            encoded.push(x[n - c - 1]);
            encoded.push(y[r]);

            i += 1;
        }
    }

    encoded
}

/// Given an encoded bdd stream for an `n x m` multiplier,
/// return the values for x and y as `m x n` matrices.
fn mul_bdd_decode<T: Clone>(encoded: &[T], n: usize, m: usize) -> (Vec<T>, Vec<T>) {
    assert_eq!(encoded.len(), 2 * m * n);

    let mut x = vec![encoded[0].clone(); n * m];
    let mut y = vec![encoded[0].clone(); n * m];

    let idx = |row, col| row * n + col;

    let mut start_row = m - 1;
    let mut start_col = n - 1;
    let mut i = 0;

    loop {
        let mut j = 0;

        loop {
            let r = start_row + j;

            if j > start_col || r >= m {
                break;
            }

            let c = start_col - j;

            x[idx(r, c)] = encoded[i].clone();
            y[idx(r, c)] = encoded[i + 1].clone();

            i += 2;
            j += 1;
        }

        if start_row > 0 {
            start_row -= 1;
        } else if start_col > 0 {
            start_col -= 1;
        } else {
            break;
        }
    }

    (x, y)
}

/// Compute a Bdd expressing that n of bits.len() bits are true.
///
/// # Remarks
/// Use caution, as the runtime of this algorithm is bits.len() choose n.
fn n_bits_are_true(variable_set: &BddVariableSet, bits: &[&Bdd], n: usize) -> Bdd {
    let combinations = Combinations::new(bits.len(), n).unwrap();

    let mut result = variable_set.mk_false();

    for c in combinations {
        let c = c.iter().collect::<HashSet<_>>();

        let mut clause = variable_set.mk_true();

        bits.iter().enumerate().for_each(|(i, x)| {
            if c.contains(&i) {
                clause = clause.and(x);
            } else {
                clause = clause.and(&x.not());
            }
        });

        result = result.or(&clause);
    }

    result
}

/// The cutoff point at which we stop subdividing values.
pub(crate) const CIRCUIT_CUTOFF: usize = 16;

/// Take an n-bit integer and partition it for recursive multiplication.
/// Returns the number of bits in the (lower, upper) words.
///
/// # Remarks.
/// If n is small, we place all the bits in the lower word and none in the upper word.
/// Otherwise, we place floor(n/2) in the upper word and ceil(n/2) in the lower word.
pub fn partition_integer(n: usize) -> (usize, usize) {
    if n <= CIRCUIT_CUTOFF {
        return (n, 0);
    }

    let upper = (n as f64 / 2.0).floor() as usize;
    let lower = (n as f64 / 2.0).ceil() as usize;

    (lower, upper)
}

/// Encodes a partition a gradeschool multiplication partial products for
/// use with the reduction circuit.
///
/// This function is internal to integer multiplication.
/// It assumes:
/// * The length of a >= length of b. You can commute operands to make
///   this true.
/// * Lengths of partitions a_lo, b_lo >= a_hi, b_hi, respectively.
///
/// # Panic
/// This function panics if any of the assumptions are false.
pub fn encode_gradeschool_reduction<T>(
    n: usize,
    m: usize,
    a_lo_b_lo: &[T],
    a_lo_b_hi: &[T],
    a_hi_b_lo: &[T],
    a_hi_b_hi: &[T],
) -> Vec<T>
where
    T: Copy + Clone,
{
    let (a_lo, a_hi) = partition_integer(n);
    let (b_lo, b_hi) = partition_integer(m);

    assert_eq!(a_lo_b_lo.len(), a_lo + b_lo);
    assert_eq!(a_lo_b_hi.len(), a_lo + b_hi);
    assert_eq!(a_hi_b_lo.len(), a_hi + b_lo);
    assert_eq!(a_hi_b_hi.len(), a_hi + b_hi);
    assert!(a_lo >= b_lo);
    assert!(a_hi <= a_lo);
    assert!(b_hi <= b_lo);

    let mut reduction_bits = vec![];

    const A_LO_B_LO: usize = 0;
    const A_HI_B_LO: usize = 1;
    const A_LO_B_HI: usize = 2;
    const A_HI_B_HI: usize = 3;

    let mut offsets = [
        0, // c_lo_lo
        0, // c_lo_hi
        0, // c_hi_lo
        0, // c_hi_hi
    ];

    // First section over a_lo_b_lo is b_lo bits wide.
    let run_len = b_lo;

    for i in 0..run_len {
        reduction_bits.push(a_lo_b_lo[offsets[A_LO_B_LO] + i]);
    }

    offsets[A_LO_B_LO] += run_len;

    // The second section is a_lo - b_lo bits wide.
    let run = a_lo - b_lo;

    for i in 0..run {
        reduction_bits.push(a_lo_b_lo[offsets[A_LO_B_LO] + i]);
        reduction_bits.push(a_lo_b_hi[offsets[A_LO_B_HI] + i]);
    }

    offsets[A_LO_B_LO] += run;
    offsets[A_LO_B_HI] += run;

    // The third section is b_lo bits wide.
    let run = b_lo;

    for i in 0..run {
        reduction_bits.push(a_lo_b_lo[offsets[A_LO_B_LO] + i]);
        reduction_bits.push(a_hi_b_lo[offsets[A_HI_B_LO] + i]);
        reduction_bits.push(a_lo_b_hi[offsets[A_LO_B_HI] + i]);
    }

    offsets[A_LO_B_LO] += run;
    offsets[A_HI_B_LO] += run;
    offsets[A_LO_B_HI] += run;

    // The fourth section is b_hi bits wide.
    let run = b_hi;

    for i in 0..run {
        reduction_bits.push(a_hi_b_lo[offsets[A_HI_B_LO] + i]);
        reduction_bits.push(a_lo_b_hi[offsets[A_LO_B_HI] + i]);
        reduction_bits.push(a_hi_b_hi[offsets[A_HI_B_HI] + i]);
    }

    offsets[A_HI_B_LO] += run;
    offsets[A_LO_B_HI] += run;
    offsets[A_HI_B_HI] += run;

    // The fifth section is a_hi - b_hi bits wide.
    let run = a_hi - b_hi;

    for i in 0..run {
        reduction_bits.push(a_hi_b_lo[offsets[A_HI_B_LO] + i]);
        reduction_bits.push(a_hi_b_hi[offsets[A_HI_B_HI] + i]);
    }

    offsets[A_HI_B_LO] += run;
    offsets[A_HI_B_HI] += run;

    // The sixth section is b_hi bits wide.
    let run = b_hi;

    for i in 0..run {
        reduction_bits.push(a_hi_b_hi[offsets[A_HI_B_HI] + i]);
    }

    reduction_bits
}

/// Generate a 4-way addition reduction of the partial outputs of each step of the divide-and-conquer
/// multiplication algorithm.
pub fn gradeschool_reduce(n: usize, m: usize) -> MuxCircuit {
    match (n, m) {
        (64, 64) => {
            bincode::deserialize(include_bytes!("data/gradeschool-reduction-n64-m64")).unwrap()
        }
        _ => gradeschool_reduce_impl(MultiplierParams { n, m }),
    }
}

/// Create a circuit that reduces the f partial multiplication terms in the
/// gradeschool algorithm. Namely given x = a | b, y = c | d, this computes
/// the 4-term sum reduction of the partial multiplications (a_lo * b_lo,
/// a_hi * b_lo, a_lo * b_hi, a_hi * b_hi).
///
/// # Remarks
/// n and m are the number of bits in the left and right operands (respectively).
/// We require n >= m, which you can ensure is true by commuting the
/// multiplication operands if necessary.
///  
/// This algorithm assumes the partitioning provided in [`partition_integer`].
///
/// Observe that adding the partial products yields the following:
/// $$\begin{matrix}
/// &&&& a_h & a_l \\
/// \times&&&& b_h & b_l \\
/// \hline
/// &&&&& c_0 \\
/// &&&&c_0+c_1& \\
/// &&&c_0+c_1+c_2&& \\
/// &&c_1+c_2+c_3 &&& \\
/// &c_2+c_3 &&&& \\
/// c_3 &&&&& \\
/// \hline \\
/// \mathbf{length (bits)} \\
/// \ell(b_h) & \ell(a_h) - \ell(b_h) & \ell(b_h) & \ell(b_l) & \ell(a_l)-\ell(b_l) & \ell(b_l) \\
/// \end{matrix}$$
///
pub fn gradeschool_reduce_impl(params: MultiplierParams) -> MuxCircuit {
    let MultiplierParams { n, m } = params;

    assert!(n >= m);

    let (a_lo, a_hi) = partition_integer(n);
    let (b_lo, b_hi) = partition_integer(m);

    // The length of the encoded input containing partial products
    let len = 2 * (m + n);

    let variable_set = BddVariableSet::new_anonymous(len as u16);
    let vars = variable_set.variables();
    let vars = vars
        .iter()
        .map(|x| variable_set.mk_var(*x))
        .collect::<Vec<_>>();

    let mut result = vec![variable_set.mk_false(); m + n];
    let mut in_offset = 0;
    let mut out_offset = 0;

    // Section 0 has no carries, while section 2 contains 1 carry for 2-input addition.
    // Sections 2 through 6 require enough carries for general 3-input addition.
    // Up to 2 carries for the current digit.
    let mut c_0 = variable_set.mk_false();
    let mut c_1 = variable_set.mk_false();

    // Up to 1 carry for the next digit.
    let mut c_2 = variable_set.mk_false();

    // Section 1 sums 1 integer (i.e. just output the input)
    let run = b_lo;

    for (i, result) in result.iter_mut().enumerate() {
        *result = vars[out_offset + i].clone();
    }

    in_offset += run;
    out_offset += run;

    // Section 2 sums over 2 integers
    let run = a_lo - b_lo;

    for i in 0..run {
        let a = &vars[in_offset + 2 * i];
        let b = &vars[in_offset + 2 * i + 1];

        let operands = [a, b, &c_0.clone()];

        let two_true = n_bits_are_true(&variable_set, &operands, 2);
        let three_true = n_bits_are_true(&variable_set, &operands, 3);

        result[out_offset + i] = a.xor(b).xor(&c_0);

        c_0 = two_true.or(&three_true);
    }

    in_offset += 2 * run;
    out_offset += run;

    // Section 3 is of length b_lo and section 4 is of length b_hi
    // Sections 3, 4 sum over 3 integers.
    let run = b_lo + b_hi;

    for i in 0..run {
        let a = &vars[in_offset + 3 * i];
        let b = &vars[in_offset + 3 * i + 1];
        let c = &vars[in_offset + 3 * i + 2];

        // Sum is xor of 3 operands and 2 carries for this place.
        result[out_offset + i] = a.xor(b).xor(c).xor(&c_0.clone()).xor(&c_1.clone());

        let operands = [a, b, c, &c_0, &c_1];

        let two_true = n_bits_are_true(&variable_set, &operands, 2);
        let three_true = n_bits_are_true(&variable_set, &operands, 3);
        let four_true = n_bits_are_true(&variable_set, &operands, 4);
        let five_true = n_bits_are_true(&variable_set, &operands, 5);

        // c_0 is true when 2, 3 or 5 of this digit's operands are true.
        c_0 = two_true.or(&three_true);

        // Move c_2 down to the next digit's carry.
        c_1 = c_2.clone();

        // c_2 is true when 4 or 5 of this digit's operands are set.
        c_2 = four_true.or(&five_true);
    }

    in_offset += 3 * run;
    out_offset += run;

    // Section 5 sums over 2 integers
    let run = a_hi - b_hi;

    for i in 0..run {
        let a = &vars[in_offset + 2 * i];
        let b = &vars[in_offset + 2 * i + 1];

        let operands = [a, b, &c_0.clone(), &c_1.clone()];

        let two_true = n_bits_are_true(&variable_set, &operands, 2);
        let three_true = n_bits_are_true(&variable_set, &operands, 3);
        let four_true = n_bits_are_true(&variable_set, &operands, 4);

        result[out_offset + i] = a.xor(b).xor(&c_0).xor(&c_1);

        c_0 = two_true.or(&three_true);
        c_1 = c_2.clone();
        c_2 = four_true;
    }

    in_offset += 2 * run;
    out_offset += run;

    // Section 6 propagates carries into a_hi * b_hi
    let run = b_hi;

    for i in 0..run {
        let a = &vars[in_offset + i];

        // The first bit can receive up to 2 1 carries and a 2 carry. However, it can never
        // produce a 2 as a carry because it's only reducing up to 3 bits.
        if i == 0 {
            result[out_offset + i] = a.xor(&c_0).xor(&c_1);

            let operands = [a, &c_0.clone(), &c_1.clone()];

            let two_true = n_bits_are_true(&variable_set, &operands, 2);
            let three_true = n_bits_are_true(&variable_set, &operands, 3);

            c_0 = two_true.or(&three_true);

            c_1 = c_2.clone();
        } else if i == 1 {
            // The second bit can receive up to 2 1 carries, but never a 2 carry. It can
            // produce up to 1 1 carry.
            result[out_offset + i] = a.xor(&c_0).xor(&c_1);

            let operands = [a, &c_0.clone(), &c_1.clone()];

            let two_true = n_bits_are_true(&variable_set, &operands, 2);
            let three_true = n_bits_are_true(&variable_set, &operands, 3);

            c_0 = two_true.or(&three_true);
        } else {
            // Subsequent bits can only receive at most 1 carry.
            result[out_offset + i] = a.xor(&c_0);

            c_0 = a.and(&c_0);
        }
    }

    let mut circuit = MuxCircuit::from(result.as_slice());
    circuit.optimize();

    circuit
}

#[cfg(test)]
mod tests {
    use biodivine_lib_bdd::BddValuation;
    use rand::{RngCore, thread_rng};

    use crate::{graph_ops::Bit, test_mux_circuit, util::try_to_bits};

    use super::*;

    #[test]
    fn multiply_circuit() {
        fn case(n: usize, m: usize) {
            let circuit = unsigned_multiplier(n, m);

            dbg!(circuit.metrics());

            for _ in 0..100 {
                let a_raw = thread_rng().next_u64() % (0x1 << n) as u64;
                let b_raw = thread_rng().next_u64() % (0x1 << m) as u64;

                let a = try_to_bits(a_raw, n).unwrap();
                let b = try_to_bits(b_raw, m).unwrap();

                let interleaved = a
                    .iter()
                    .copied()
                    .chain(b.iter().copied())
                    .collect::<Vec<_>>();

                assert_eq!(interleaved.len(), n + m);

                let res = test_mux_circuit(&circuit, &interleaved);

                assert_eq!(res.len(), n + m);

                let expected = (a_raw as u128).wrapping_mul(b_raw as u128);

                let mut actual = 0;

                for (i, b) in res.iter().enumerate() {
                    actual |= (b.0 as u128) << i;
                }

                assert_eq!(expected, actual);
            }
        }

        case(2, 2);
        case(3, 3);
        case(4, 4);
        case(5, 5);
        case(6, 6);
        case(7, 7);
        case(8, 8);

        // Mismatched dimensions
        case(6, 4);
        case(6, 5);
        case(6, 7);
        case(6, 8);

        case(4, 6);
        case(5, 6);
        case(7, 6);
        case(8, 6);
    }

    #[test]
    fn test_n_bits_are_true() {
        let num_vars = 5;

        let variable_set = BddVariableSet::new_anonymous(num_vars);
        let vars = variable_set.variables();
        let vars = vars
            .iter()
            .map(|x| variable_set.mk_var(*x))
            .collect::<Vec<_>>();

        let vars_ref = vars.iter().collect::<Vec<_>>();

        for i in 0..=5 {
            let expr = n_bits_are_true(&variable_set, &vars_ref, i);

            for j in 0..(0x1usize << num_vars) {
                let eval = (0..num_vars)
                    .enumerate()
                    .map(|(i, _)| ((j >> i) & 0x1) == 1)
                    .collect::<Vec<_>>();
                let eval = BddValuation::new(eval);

                assert_eq!(expr.eval_in(&eval), j.count_ones() as usize == i);
            }
        }
    }

    #[test]
    fn gradeschool_reduce_works() {
        fn case(n: usize, m: usize) {
            let circuit = gradeschool_reduce(n, m);

            fn as_bits(val: u128, len: usize) -> Vec<Bit> {
                assert!(val < (0x1 << len));

                let mut result = vec![Bit::default(); len];

                for (i, result) in result.iter_mut().enumerate() {
                    *result = Bit::from((val >> i) & 0x1 == 1);
                }

                result
            }

            for _ in 0..100 {
                // Do everything as u128 to prevent overflow.
                let a = (rand::thread_rng().next_u32() % (0x1 << n)) as u128;
                let b = (rand::thread_rng().next_u32() % (0x1 << m)) as u128;

                let (n_lo, n_hi) = partition_integer(n);
                let (m_lo, m_hi) = partition_integer(m);

                let decompose = |x: u128, lower: usize| (x & ((0x1 << lower) - 1), x >> lower);

                let (a_lo, a_hi) = decompose(a, n_lo);
                let (b_lo, b_hi) = decompose(b, m_lo);

                // lower * lower bits
                let a_lo_b_lo = a_lo * b_lo;

                // lower * upper bits
                let a_lo_b_hi = a_lo * b_hi;
                let a_hi_b_lo = a_hi * b_lo;

                // upper * upper bits
                let a_hi_b_hi = a_hi * b_hi;

                let expected = a.checked_mul(b).unwrap();

                // sanity check
                assert_eq!(
                    a_lo_b_lo
                        + (a_lo_b_hi << m_lo)
                        + (a_hi_b_lo << n_lo)
                        + (a_hi_b_hi << (m_lo + n_lo)),
                    expected
                );

                let a_lo_b_lo = as_bits(a_lo_b_lo, n_lo + m_lo);
                let a_lo_b_hi = as_bits(a_lo_b_hi, n_lo + m_hi);
                let a_hi_b_lo = as_bits(a_hi_b_lo, n_hi + m_lo);
                let a_hi_b_hi = as_bits(a_hi_b_hi, n_hi + m_hi);

                let inputs = encode_gradeschool_reduction(
                    n, m, &a_lo_b_lo, &a_lo_b_hi, &a_hi_b_lo, &a_hi_b_hi,
                );

                let ans = test_mux_circuit(&circuit, &inputs);

                let mut actual = 0;

                for (i, val) in ans.iter().enumerate() {
                    actual |= (val.0 as u128) << i;
                }

                println!("actual:   0b{:b}", actual);
                println!("expected: 0b{:b}", expected);

                assert_eq!(actual, expected);
            }
        }

        for n in 17..21 {
            for m in 17..21 {
                if n >= m {
                    case(n, m);
                }
            }
        }
    }

    #[test]
    fn can_partition_integer() {
        for i in 1..128 {
            let (lo, hi) = partition_integer(i);

            assert_eq!(lo + hi, i);
            assert!(lo >= hi);
        }
    }

    #[test]
    fn six_reduction_sections_are_correct_length() {
        for n in 1..128 {
            for m in 1..(n + 1) {
                let (a_lo, a_hi) = partition_integer(n);
                let (b_lo, b_hi) = partition_integer(m);

                // One can derive this formula with a few diagrams and
                // a bit of meth. This is the sum of the lengths described in
                // [`gradeschool_reduce`]`
                let actual = b_lo + (a_lo - b_lo) + b_lo + b_hi + (a_hi - b_hi) + b_hi;

                assert_eq!(m + n, actual);
            }
        }
    }
}
