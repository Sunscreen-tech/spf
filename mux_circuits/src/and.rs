use biodivine_lib_bdd::BddVariableSet;

use super::MuxCircuit;

/// Crate a bitwise-and circuit for 2 integers of bit length `inputs`.
pub fn make_and_circuit(inputs: u16) -> MuxCircuit {
    let variable_set = BddVariableSet::new_anonymous(2 * inputs);
    let vars = variable_set.variables();

    let mut and = vec![variable_set.mk_false(); inputs as usize];

    for i in 0..inputs as usize {
        let a = variable_set.mk_var(vars[2 * i]);
        let b = variable_set.mk_var(vars[2 * i + 1]);

        and[i] = a.and(&b);
    }

    let mut circuit = MuxCircuit::from(and.as_slice());
    circuit.optimize();

    circuit
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, thread_rng};

    use crate::{graph_ops::Bit, test_mux_circuit};

    use super::make_and_circuit;

    #[test]
    fn and_circuit() {
        for i in 1..=9 {
            let circuit = make_and_circuit(i);

            for _ in 0..10 {
                let a = (0..i)
                    .map(|_| thread_rng().next_u32() % 2 == 1)
                    .collect::<Vec<_>>();
                let b = (0..i)
                    .map(|_| thread_rng().next_u32() % 2 == 1)
                    .collect::<Vec<_>>();

                let inputs = a
                    .iter()
                    .zip(b.iter())
                    .flat_map(|(a, b)| [Bit(*a), Bit(*b)])
                    .collect::<Vec<_>>();

                let actual = test_mux_circuit(&circuit, &inputs);

                let expected = a
                    .iter()
                    .zip(b.iter())
                    .map(|(a, b)| Bit(a & b))
                    .collect::<Vec<_>>();

                assert_eq!(actual, expected);
            }
        }
    }
}
