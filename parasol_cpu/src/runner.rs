use parasol_runtime::ComputeKey;

use crate::{Args, Memory, error::Result};

/// Runs a program by generating a new [`crate::FheComputer`]. This function is meant
/// for simple testing of a program; for full applications see the
/// [`crate::FheComputer`] struct.
pub fn run_program<T>(
    _compute_key: ComputeKey,
    _memory: Memory,
    _program_name: &str,
    _arguments: Args<T>,
    _gas_limit: u32,
) -> Result<(u32, T)> {
    todo!();
}

#[cfg(test)]
mod tests {
    // #[test]
    // fn test_run_program() {
    //     let compute_key = get_compute_key_128();
    //     let compute_key: &ComputeKey = compute_key.borrow();
    //     let enc = Encryption::default();

    //     let bound = 20u8;
    //     let a = 6u8;
    //     let b = 3u8;

    //     let buffer_0 = buffer_from_value_128(bound, &enc, true);
    //     let buffer_1 = buffer_from_value_128(a, &enc, true);
    //     let buffer_2 = buffer_from_value_128(b, &enc, true);
    //     let output_buffer = buffer_from_value_128(0u8, &enc, true);

    //     let arguments = vec![buffer_0, buffer_1, buffer_2, output_buffer];

    //     let (_gas, result) = run_program(compute_key.clone(), CMUX_ELF, "cmux", &arguments, 300_000).unwrap();

    //     let output = result[3]
    //         .cipher_try_into_value::<u8>(&enc, &get_secret_keys_128())
    //         .unwrap();
    //     let expected = if bound > 10 { a } else { b };

    //     assert_eq!(expected, output);
    // }
}
