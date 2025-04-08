use biodivine_lib_bdd::BddVariableSet;

use super::MuxCircuit;

/// Create a ripple carry adder between an n-bit integer and an m-bit integer.
/// Produces a max(n, m) + 1 bit value (the top bit is the carry out).
///
/// # Remarks
/// If cin is true, then the carry in appears as the first bit. If not, there is
/// no carry-in bit.  Following the the possible carry bit, a and b are
/// interleaved until the bits of the shorter value are exhausted. The remaining
/// bits are those in the longer value.
pub fn ripple_carry_adder(n: usize, m: usize, cin: bool) -> MuxCircuit {
    assert!(m > 0);
    assert!(n > 0);

    let min_len = usize::min(m, n);
    let max_len = usize::max(m, n);
    let cin_offset = cin as usize;
    let in_len = m + n + cin_offset;

    let variable_set = BddVariableSet::new_anonymous(in_len as u16);
    let vars = variable_set.variables();
    let vars = vars
        .iter()
        .map(|x| variable_set.mk_var(*x))
        .collect::<Vec<_>>();

    let mut carry = if cin {
        vars[0].clone()
    } else {
        variable_set.mk_false()
    };

    let mut sum = vec![variable_set.mk_true(); max_len + 1];

    for i in 0..min_len {
        let a = &vars[cin_offset + 2 * i];
        let b = &vars[cin_offset + 2 * i + 1];

        let a_xor_b = a.xor(b);

        sum[i] = carry.xor(&a_xor_b);
        carry = a_xor_b.and(&carry).or(&a.and(b));
    }

    for i in 0..max_len - min_len {
        let a = &vars[2 * min_len + i + cin_offset];
        sum[i + min_len] = carry.xor(a);
        carry = a.and(&carry);
    }

    sum[max_len] = carry;

    MuxCircuit::from(sum.as_slice())
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, RngCore};

    use crate::{convert_value_to_bits, graph_ops::Bit, test_mux_circuit};

    use super::*;

    #[test]
    fn ripple_carry_circuit() {
        fn case<const N: usize>(cin: bool) {
            let circuit = ripple_carry_adder(N, N, cin);

            for _ in 0..100 {
                let a_raw = thread_rng().next_u64() & ((0x1 << N) - 1);
                let b_raw = thread_rng().next_u64() & ((0x1 << N) - 1);

                let a = convert_value_to_bits(a_raw as u128, N as u32)
                    .iter()
                    .map(|x| Bit(*x))
                    .collect::<Vec<_>>();
                let b = convert_value_to_bits(b_raw as u128, N as u32)
                    .iter()
                    .map(|x| Bit(*x))
                    .collect::<Vec<_>>();

                let carry_in = if cin {
                    vec![Bit(thread_rng().next_u64() % 2 == 1)]
                } else {
                    vec![]
                };

                let interleaved = carry_in
                    .iter()
                    .copied()
                    .chain(a.iter().zip(b.iter()).flat_map(|(a, b)| [*a, *b]))
                    .collect::<Vec<_>>();

                let res = test_mux_circuit(&circuit, &interleaved);

                assert_eq!(res.len(), N + 1);

                let expected = a_raw.wrapping_add(b_raw) + (cin && carry_in[0].0) as u64;

                let mut actual = 0;

                for (i, b) in res.iter().enumerate() {
                    actual |= (b.0 as u64) << i;
                }

                assert_eq!(expected, actual);
            }
        }

        for cin in [false, true] {
            case::<4>(cin);
            case::<32>(cin);
        }
    }
}
