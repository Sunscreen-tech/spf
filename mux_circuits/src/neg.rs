use biodivine_lib_bdd::BddVariableSet;

use super::MuxCircuit;

/// Create 2's complement of one n-bit integer
/// Produces a n-bit value
pub fn negator(n: usize) -> MuxCircuit {
    assert!(n > 0);

    let variable_set = BddVariableSet::new_anonymous(n as u16);
    let vars = variable_set.variables();
    let vars = vars
        .iter()
        .map(|x| variable_set.mk_var(*x))
        .collect::<Vec<_>>();

    let mut flip = variable_set.mk_false();

    let mut neg = vec![variable_set.mk_true(); n];

    // copy the bits until you see 1 for the first time, then after that flip the bits
    for i in 0..n {
        neg[i] = flip.xor(&vars[i]);
        flip = flip.or(&vars[i]);
    }

    MuxCircuit::from(neg.as_slice())
}

#[cfg(test)]
mod tests {
    use std::fmt::{Display, Formatter};

    use rand::{RngCore, thread_rng};

    use crate::{
        convert_value_to_bits, graph_ops::Bit, test_mux_circuit,
        util::arbitrary_width_borrowing_sub,
    };

    use super::*;

    #[derive(Debug, Clone, Copy)]
    struct Case {
        n: usize,
        b: u64,
    }

    impl Display for Case {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "Case {{ n: {}, b: {} }}", self.n, self.b)
        }
    }

    fn random_case() -> Case {
        let n = (thread_rng().next_u32() as usize % 32) + 1;
        let b = thread_rng().next_u64() & ((0x1 << n) - 1);

        Case { n, b }
    }

    #[test]
    fn negator_cicruit() {
        fn test(case: Case) {
            let Case { n, b } = case;

            let circuit = negator(n);

            let inputs = convert_value_to_bits(b as u128, n as u32)
                .iter()
                .map(|x| Bit(*x))
                .collect::<Vec<_>>();

            let res = test_mux_circuit(&circuit, &inputs);

            assert_eq!(res.len(), n);

            let (expected_neg, _) = arbitrary_width_borrowing_sub(0, b as u128, 0, n as u32);

            let mut actual_neg = 0;

            for (i, bit) in res.iter().enumerate() {
                actual_neg |= (bit.0 as u64) << i;
            }

            assert_eq!(expected_neg, actual_neg as u128, "case: {}", &case);
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
