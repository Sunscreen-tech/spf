use biodivine_lib_bdd::{Bdd, BddVariableSet};

use super::MuxCircuit;

/// Compute the integer log base 2 of a number, rounded up.
fn ilog2_rounded_up(x: u16) -> u32 {
    if x == 0 {
        0
    } else if x.is_power_of_two() {
        x.ilog2()
    } else {
        x.ilog2() + 1
    }
}

/// Bit shift circuit made from 2:1 muxes.
///
/// # Arguments
///
/// * `inputs` - The number of bits in the input. Note that the input should be
///   specified MSB first.
/// * `shift_size` - The number of bits in the shift. Note that the shift should
///   be specified MSB first.
/// * `right` - Whether to shift right or left.
/// * `zeros` - Whether to fill the shifted bits with zeros.
pub fn bitshift(inputs: u16, shift_size: u16, right: bool, zeros: bool) -> MuxCircuit {
    let used_shift_bits = ilog2_rounded_up(inputs) as u16;
    let used_shift_bits = if used_shift_bits == 0 {
        1
    } else {
        used_shift_bits
    };

    assert!(
        shift_size >= used_shift_bits,
        "Shift size must be at least the number of bits needed to represent the input size. Got {} shift bits, needed {} shift bits for input size {}.", shift_size, used_shift_bits, inputs
    );

    // To handle this case we would need a modulus circuit, which is
    // non-trivial to implement.
    if !zeros && !inputs.is_power_of_two() {
        panic!("Shift without zeros is only supported for power of two inputs.");
    }

    let variable_set = BddVariableSet::new_anonymous(inputs + shift_size);
    let vars = variable_set.variables();
    let excess_shift_vars = (0..(shift_size - used_shift_bits))
        .map(|x| variable_set.mk_var(vars[(inputs + x) as usize]))
        .collect::<Vec<_>>();
    let used_shift_vars = ((shift_size - used_shift_bits)..shift_size)
        .map(|x| variable_set.mk_var(vars[(inputs + x) as usize]))
        .collect::<Vec<_>>();

    let mut result = (0..inputs)
        .map(|i| variable_set.mk_var(vars[i as usize]))
        .collect::<Vec<_>>();

    // Making a barrel shifter out of 2:1 muxes.
    for (i, shift_log) in (0..used_shift_bits).rev().enumerate() {
        let shift = 1 << shift_log;
        let select = &used_shift_vars[i];

        let mut intermediate = result.clone();

        // The variables are specified in the circuit as big endian, hence the
        // shift directions are what we expect.
        if right {
            intermediate.rotate_right(shift % (inputs as usize));
        } else {
            intermediate.rotate_left(shift % (inputs as usize));
        }

        for input_index in 0..inputs as usize {
            let not_shifted_var = result[input_index].clone();

            let shifted_var = match (right, zeros) {
                (true, true) => {
                    if input_index < shift {
                        variable_set.mk_false()
                    } else {
                        intermediate[input_index].clone()
                    }
                }
                (false, true) => {
                    if input_index >= (inputs as usize - shift) {
                        variable_set.mk_false()
                    } else {
                        intermediate[input_index].clone()
                    }
                }
                (true, false) => intermediate[input_index].clone(),
                (false, false) => intermediate[input_index].clone(),
            };

            result[input_index] = Bdd::if_then_else(select, &shifted_var, &not_shifted_var);
        }
    }

    // Now mux in the higher order wrapped select bits; if any are 1 then the
    // entire output vector is zero.
    if zeros {
        let mut clear_bit = variable_set.mk_false();
        for excess_shift_bit in excess_shift_vars {
            clear_bit = clear_bit.or(&excess_shift_bit);
        }

        for res in result.iter_mut() {
            *res = Bdd::if_then_else(&clear_bit, &variable_set.mk_false(), &res.clone());
        }
    }

    let mut circuit = MuxCircuit::from(result.as_slice());
    circuit.optimize();

    circuit
}

#[cfg(test)]
mod tests {
    use std::fmt::{Display, Formatter};

    use crate::{graph_ops::Bit, test_mux_circuit};

    use super::bitshift;

    #[derive(Debug, Clone, Copy)]
    struct Case {
        width: u16,
        shift: u16,
        value: u16,
        right: bool,
        zeros: bool,
    }

    impl Display for Case {
        fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
            write!(
                f,
                "Case {{ width: {}, shift: {}, right: {}, zeros: {}, value: {} }}",
                self.width, self.shift, self.right, self.zeros, self.value
            )
        }
    }

    fn run_case(case: Case) {
        let Case {
            width,
            shift,
            value,
            right,
            zeros,
        } = case;

        let circuit = bitshift(width, width, right, zeros);

        let mut expected_bits = (0..width)
            .rev()
            .map(|i| Bit((value >> i) & 0x1 == 1))
            .collect::<Vec<_>>();

        if right {
            expected_bits.rotate_right((shift % width) as usize);

            // Clear out top shift bits if zero
            if zeros {
                expected_bits
                    .iter_mut()
                    .take(shift as usize)
                    .for_each(|x| *x = Bit(false));
            }
        } else {
            expected_bits.rotate_left((shift % width) as usize);

            // Clear out bottom shift bits if zero
            if zeros {
                expected_bits
                    .iter_mut()
                    .rev()
                    .take(shift as usize)
                    .for_each(|x| *x = Bit(false));
            }
        }

        // Map back into a u32
        let expected = expected_bits
            .iter()
            .rev()
            .enumerate()
            .map(|(i, &Bit(x))| (x as u32) << i)
            .sum::<u32>();

        let value_as_bits = (0..width)
            .rev()
            .map(|i| (value >> i) & 1 == 1)
            .collect::<Vec<_>>();
        let shift_input = (0..width)
            .rev()
            .map(|i| (shift >> i) & 1 == 1)
            .collect::<Vec<_>>();

        // create a new vector with shift appended to a
        let inputs = value_as_bits
            .iter()
            .chain(shift_input.iter())
            .map(|&x| Bit(x))
            .collect::<Vec<_>>();

        let actual_bits = test_mux_circuit(&circuit, &inputs);

        // map back to a u32
        let actual = actual_bits
            .iter()
            .rev()
            .enumerate()
            .map(|(i, &Bit(x))| (x as u32) << i)
            .sum::<u32>();

        let print_width = width as usize;
        if expected != actual {
            println!(
                "width: {}, shift: {}, right: {}, zeros: {}, value: {:#print_width$b}, expected: {:#print_width$b}, actual: {:#print_width$b}",
                width, shift, right, zeros, value, &expected, &actual
            );
            println!("{}", &case);
            panic!("Mismatch");
        }
    }

    #[test]
    fn bitshift_circuit() {
        let bad_cases = [
            // These fail because we don't support shifting without zeros for
            // non-power of two inputs.
            // Case {
            //     width: 3,
            //     shift: 4,
            //     right: false,
            //     zeros: false,
            //     value: 1,
            // },
            // Case {
            //     width: 5,
            //     shift: 8,
            //     right: false,
            //     zeros: false,
            //     value: 1,
            // },
        ];

        for case in bad_cases {
            run_case(case);
        }

        for zeros in [false, true] {
            for right in [false, true] {
                for width in 1..=6u16 {
                    let mask = (1 << width) - 1;

                    // Skip the cases where we would need to perform a modulus
                    // operation.
                    if !zeros && !(width.is_power_of_two()) {
                        continue;
                    }

                    // Check every value
                    for value in 0..(1 << width) {
                        let value = value & mask;

                        for shift in 0..(1 << width) {
                            let case = Case {
                                width,
                                shift: shift & mask,
                                value,
                                right,
                                zeros,
                            };
                            run_case(case);
                        }
                    }
                }
            }
        }
    }
}
