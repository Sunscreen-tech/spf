use biodivine_lib_bdd::BddVariableSet;

use super::MuxCircuit;

/// Create a subtraction with borrow circuit between an two n-bit integers.
/// Produces a n bit value (the top bit is the borrow out).
///
/// # Remarks
/// If borrow_in is true, then the borrow in appears as the first bit. If not,
/// there is no borrow-in bit.  Following the the possible borrow bit, a and b
/// are interleaved.
pub fn full_subtractor(n: usize, bin: bool) -> MuxCircuit {
    assert!(n > 0);

    let bin_offset = bin as usize;
    let in_len = 2 * n + bin_offset;

    let variable_set = BddVariableSet::new_anonymous(in_len as u16);
    let vars = variable_set.variables();
    let vars = vars
        .iter()
        .map(|x| variable_set.mk_var(*x))
        .collect::<Vec<_>>();

    let mut borrow = if bin {
        vars[0].clone()
    } else {
        variable_set.mk_false()
    };

    let mut diff = vec![variable_set.mk_true(); n + 1];

    // diff = a ⊕ b ⊕ borrow_in
    // borrow = borrow_in(a ⊕ b)' + a'b
    for i in 0..n {
        let a = &vars[bin_offset + 2 * i];
        let b = &vars[bin_offset + 2 * i + 1];

        let a_xor_b = a.xor(b);

        diff[i] = borrow.xor(&a_xor_b);
        borrow = borrow.and_not(&a_xor_b).or(&b.and_not(a));
    }

    diff[n] = borrow;

    MuxCircuit::from(diff.as_slice())
}

#[cfg(test)]
mod tests {
    use std::fmt::{Display, Formatter};

    use rand::{thread_rng, RngCore};

    use crate::{
        convert_value_to_bits, graph_ops::Bit, test_mux_circuit,
        util::arbitrary_width_borrowing_sub,
    };

    use super::*;

    #[derive(Debug, Clone, Copy)]
    struct Case {
        n: usize,
        a: u64,
        b: u64,
        bin: bool,
        use_borrow_in: bool,
    }

    impl Display for Case {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "Case {{ n: {}, a: {}, b: {}, bin: {}, use_borrow_in: {} }}",
                self.n, self.a, self.b, self.bin, self.use_borrow_in
            )
        }
    }

    fn random_case() -> Case {
        let n = (thread_rng().next_u32() as usize % 32) + 1;
        let a = thread_rng().next_u64() & ((0x1 << n) - 1);
        let b = thread_rng().next_u64() & ((0x1 << n) - 1);
        let bin = thread_rng().next_u64() % 2 == 1;
        let use_borrow_in = thread_rng().next_u64() % 2 == 1;

        Case {
            n,
            a,
            b,
            bin,
            use_borrow_in,
        }
    }

    #[test]
    fn full_subtractor_circuit() {
        fn test(case: Case) {
            let Case {
                n,
                a,
                b,
                bin,
                use_borrow_in,
            } = case;

            let circuit = full_subtractor(n, use_borrow_in);

            let a_in = convert_value_to_bits(a as u128, n as u32)
                .iter()
                .map(|x| Bit(*x))
                .collect::<Vec<_>>();
            let b_in = convert_value_to_bits(b as u128, n as u32)
                .iter()
                .map(|x| Bit(*x))
                .collect::<Vec<_>>();

            let borrow_in = if use_borrow_in {
                vec![Bit(bin)]
            } else {
                vec![]
            };

            let interleaved = borrow_in
                .iter()
                .copied()
                .chain(a_in.iter().zip(b_in.iter()).flat_map(|(a, b)| [*a, *b]))
                .collect::<Vec<_>>();

            let res = test_mux_circuit(&circuit, &interleaved);

            assert_eq!(res.len(), n + 1);

            let (expected_diff, expected_borrow) = arbitrary_width_borrowing_sub(
                a as u128,
                b as u128,
                (use_borrow_in & bin) as u128,
                n as u32,
            );

            let mut actual_diff = 0;

            for (i, bit) in res[0..res.len() - 1].iter().enumerate() {
                actual_diff |= (bit.0 as u64) << i;
            }

            let actual_borrow = res[res.len() - 1].0;

            assert_eq!(expected_diff, actual_diff as u128, "case: {}", &case);
            assert_eq!(expected_borrow, actual_borrow as u128, "case: {}", &case)
        }

        // Cases that failed during initial testing, used to debug the circuit
        // on known failed inputs
        let known_cases = [];

        let total_cases = 1_000;
        let cases = known_cases
            .iter()
            .copied()
            .chain((0..(total_cases - known_cases.len())).map(|_| random_case()));

        for case in cases {
            test(case);
        }
    }
}
