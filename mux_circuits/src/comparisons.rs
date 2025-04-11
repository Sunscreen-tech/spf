use biodivine_lib_bdd::{Bdd, BddVariableSet};

use super::MuxCircuit;

fn equal(a: &Bdd, b: &Bdd) -> Bdd {
    a.xor(b).not()
}

fn greater_than(a: &Bdd, b: &Bdd) -> Bdd {
    a.and_not(b)
}

fn less_than(a: &Bdd, b: &Bdd) -> Bdd {
    b.and_not(a)
}

/// Check if two n-bit integers are equal.
/// Produces a 1 bit boolean value.
pub fn compare_equal(n: usize) -> MuxCircuit {
    assert!(n > 0);

    let in_len = 2 * n;

    let variable_set = BddVariableSet::new_anonymous(in_len as u16);
    let vars = variable_set.variables();
    let vars = vars
        .iter()
        .map(|x| variable_set.mk_var(*x))
        .collect::<Vec<_>>();

    let mut result = variable_set.mk_true();

    for i in 0..n {
        let a = &vars[2 * i];
        let b = &vars[2 * i + 1];

        let a_equal_b = equal(a, b);
        result = result.and(&a_equal_b);
    }

    MuxCircuit::from([result].as_slice())
}

/// Check if two n-bit integers are equal.
/// Produces a 1 bit boolean value.
pub fn compare_not_equal(n: usize) -> MuxCircuit {
    assert!(n > 0);

    let in_len = 2 * n;

    let variable_set = BddVariableSet::new_anonymous(in_len as u16);
    let vars = variable_set.variables();
    let vars = vars
        .iter()
        .map(|x| variable_set.mk_var(*x))
        .collect::<Vec<_>>();

    let mut result = variable_set.mk_true();

    for i in 0..n {
        let a = &vars[2 * i];
        let b = &vars[2 * i + 1];

        let a_equal_b = equal(a, b);
        result = result.and(&a_equal_b);
    }

    result = result.not();
    MuxCircuit::from([result].as_slice())
}

/// Compare two n-bit signed integers
/// Produces a 1 bit boolean value.
///
/// Arguments:
/// - `n`: The number of bits in the integers including the sign bit
/// - `greater`: If true, the circuit will check if a > b, otherwise it will check if a < b.
/// - `or_equal`: If true, the circuit will also check if a == b.
pub fn compare_or_maybe_equal_signed(n: usize, greater: bool, or_equal: bool) -> MuxCircuit {
    assert!(n > 0);

    let in_len = 2 * n;

    let variable_set = BddVariableSet::new_anonymous(in_len as u16);
    let vars = variable_set.variables();
    let vars = vars
        .iter()
        .map(|x| variable_set.mk_var(*x))
        .collect::<Vec<_>>();

    // special handling for the sign bit
    //
    // in case of greater, if a is 0 and b is 1 (a positive, b negative),
    // then we "override" the result to true, if a is 1 and b is 0, we
    // "override" the result to false, otherwise, we do not touch result
    //
    // in case of smaller, just invert above
    let a = &vars[2 * n - 2];
    let b = &vars[2 * n - 1];

    let force_true = if greater {
        less_than(a, b)
    } else {
        greater_than(a, b)
    };

    let force_false = if greater {
        greater_than(a, b)
    } else {
        less_than(a, b)
    };

    let mut result = unsigned_comparison_impl(variable_set, &vars[..2 * n - 2], greater, or_equal);

    result = result.or(&force_true).and_not(&force_false);

    MuxCircuit::from([result].as_slice())
}

/// Compare two n-bit integers
/// Produces a 1 bit boolean value.
///
/// Arguments:
/// - `n`: The number of bits in the integers.
/// - `greater`: If true, the circuit will check if a > b, otherwise it will check if a < b.
/// - `or_equal`: If true, the circuit will also check if a == b.
pub fn compare_or_maybe_equal(n: usize, greater: bool, or_equal: bool) -> MuxCircuit {
    assert!(n > 0);

    let in_len = 2 * n;

    let variable_set = BddVariableSet::new_anonymous(in_len as u16);
    let vars = variable_set.variables();
    let vars = vars
        .iter()
        .map(|x| variable_set.mk_var(*x))
        .collect::<Vec<_>>();

    let result = unsigned_comparison_impl(variable_set, &vars[..], greater, or_equal);

    MuxCircuit::from([result].as_slice())
}

fn unsigned_comparison_impl(
    variable_set: BddVariableSet,
    vars: &[Bdd],
    greater: bool,
    or_equal: bool,
) -> Bdd {
    let mut result = variable_set.mk_false();
    let mut a_and_b_cumprod = variable_set.mk_true();

    // Uses the following relation:
    // a > b = (a[n] > b[n]) + eq[n](a[n-1] > b[n-1]) + (eq[n]eq[n-1])(a[n-2] > b[n - 2]) + ...
    //         + (eq[n]eq[n-1]...eq[1])(a[0] > b[0])
    // where eq[i] = (a[i] ⊕ b[i])' (i.e. a[i] = b[i])
    // and a[n] > b[n] = a[n] b[n]'
    //
    // If performing a < b, we can use the same circuit, but with the inequality
    // reversed:
    // a[n] < b[n] = a[n]' b[n]
    for i in (0..(vars.len() / 2)).rev() {
        let a = &vars[2 * i];
        let b = &vars[2 * i + 1];

        let a_compare_b = if greater {
            greater_than(a, b)
        } else {
            less_than(a, b)
        };

        result = result.or(&a_compare_b.and(&a_and_b_cumprod));

        // Compute next a_and_b_cumprod after the current comparison
        let prior_equality = equal(a, b);
        a_and_b_cumprod = a_and_b_cumprod.and(&prior_equality);
    }

    if or_equal {
        result = result.or(&a_and_b_cumprod);
    }

    result
}

#[cfg(test)]
mod tests {
    use std::fmt::{Display, Formatter};

    use rand::{RngCore, thread_rng};

    use crate::convert_value_to_bits;

    use super::*;

    mod equality_tests {
        use crate::{graph_ops::Bit, test_mux_circuit};

        use super::*;

        #[derive(Debug, Clone, Copy)]
        struct Case {
            n: usize,
            a: u64,
            b: u64,
        }

        impl Display for Case {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "Case {{ n: {}, a: {}, b: {} }}", self.n, self.a, self.b,)
            }
        }

        fn random_case() -> Case {
            let n = (thread_rng().next_u32() as usize % 32) + 1;
            let a = thread_rng().next_u64() & ((0x1 << n) - 1);
            let b = thread_rng().next_u64() & ((0x1 << n) - 1);

            Case { n, a, b }
        }

        #[test]
        fn compare_equal_circuit() {
            fn test(case: Case) {
                let Case { n, a, b } = case;

                let circuit = compare_equal(n);

                let a_in = convert_value_to_bits(a as u128, n as u32)
                    .iter()
                    .map(|x| Bit(*x))
                    .collect::<Vec<_>>();
                let b_in = convert_value_to_bits(b as u128, n as u32)
                    .iter()
                    .map(|x| Bit(*x))
                    .collect::<Vec<_>>();

                let interleaved = a_in
                    .iter()
                    .zip(b_in.iter())
                    .flat_map(|(a, b)| [*a, *b])
                    .collect::<Vec<_>>();

                let res = test_mux_circuit(&circuit, &interleaved);

                assert_eq!(res.len(), 1);

                let expected = a == b;
                let actual = res[0].0;

                assert_eq!(expected, actual, "Failed case: {}", case);
            }

            // Cases that failed during initial testing, used to debug the circuit
            // on known failed inputs
            let known_cases = [];

            let total_cases = 100;
            let cases = known_cases
                .iter()
                .copied()
                .chain((0..(total_cases - known_cases.len())).map(|_| random_case()));

            for case in cases {
                test(case);
            }
        }
    }
    mod inequality_tests {

        use crate::{graph_ops::Bit, test_mux_circuit};

        use super::*;

        #[derive(Debug, Clone, Copy)]
        struct Case {
            n: usize,
            a: u64,
            b: u64,
            greater: bool,
            equality: bool,
        }

        impl Display for Case {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "Case {{ n: {}, a: {}, b: {}, greater: {}, equality: {} }}",
                    self.n, self.a, self.b, self.greater, self.equality
                )
            }
        }

        fn random_case() -> Case {
            let n = (thread_rng().next_u32() as usize % 32) + 1;
            let a = thread_rng().next_u64() & ((0x1 << n) - 1);

            // With a 1/4 chance let a == b
            let same_value = thread_rng().next_u64() & 0x3;
            let b = if same_value == 0 {
                a
            } else {
                thread_rng().next_u64() & ((0x1 << n) - 1)
            };

            let greater = thread_rng().next_u64() & 0x1 == 0;
            let equality = thread_rng().next_u64() & 0x1 == 0;

            Case {
                n,
                a,
                b,
                greater,
                equality,
            }
        }

        fn test(
            i: usize,
            case: Case,
            circuit_gen: fn(usize, bool, bool) -> MuxCircuit,
            proc: fn(u64, usize) -> i64,
        ) {
            let Case {
                n,
                a,
                b,
                greater,
                equality,
            } = case;

            let circuit = circuit_gen(n, greater, equality);

            let a_in = convert_value_to_bits(a as u128, n as u32)
                .iter()
                .map(|x| Bit(*x))
                .collect::<Vec<_>>();
            let b_in = convert_value_to_bits(b as u128, n as u32)
                .iter()
                .map(|x| Bit(*x))
                .collect::<Vec<_>>();

            let interleaved = a_in
                .iter()
                .zip(b_in.iter())
                .flat_map(|(a, b)| [*a, *b])
                .collect::<Vec<_>>();

            let res = test_mux_circuit(&circuit, &interleaved);

            assert_eq!(res.len(), 1);

            let expected = match (greater, equality) {
                (false, false) => proc(a, n) < proc(b, n),
                (false, true) => proc(a, n) <= proc(b, n),
                (true, false) => proc(a, n) > proc(b, n),
                (true, true) => proc(a, n) >= proc(b, n),
            };

            let actual = res[0].0;

            assert_eq!(expected, actual, "Failed case #{i}: {case}");
        }

        #[test]
        fn compare_maybe_equal_circuit() {
            // Cases that failed during initial testing, used to debug the circuit
            // on known failed inputs
            let known_cases = [];

            let total_cases = 400;
            let cases = known_cases
                .iter()
                .copied()
                .chain((0..(total_cases - known_cases.len())).map(|_| random_case()));

            for (i, case) in cases.enumerate() {
                test(i, case, compare_or_maybe_equal, |num: u64, _| num as i64);
            }
        }

        #[test]
        fn compare_maybe_equal_unsigned_circuit() {
            // Cases that failed during initial testing, used to debug the circuit
            // on known failed inputs
            let known_cases = [];

            let total_cases = 400;
            let cases = known_cases
                .iter()
                .copied()
                .chain((0..(total_cases - known_cases.len())).map(|_| random_case()));

            for (i, case) in cases.enumerate() {
                test(i, case, compare_or_maybe_equal_signed, |num, width| {
                    let sign = 0x1u64 << (width - 1);
                    if sign & num == 0 {
                        num as i64
                    } else {
                        -(((sign << 1) - num) as i64)
                    }
                });
            }
        }
    }
}
