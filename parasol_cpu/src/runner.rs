use std::sync::Arc;

use parasol_runtime::{ComputeKey, Encryption, Evaluation};

use crate::{Args, Error, FheComputer, Memory, ToArg, error::Result};

/// Runs a program by generating a new [`crate::FheComputer`]. This function is meant
/// for simple testing of a program; for full applications see the
/// [`crate::FheComputer`] struct.
pub fn run_program<T: ToArg>(
    compute_key: ComputeKey,
    elf_file: &[u8],
    program_name: &str,
    arguments: Args<T>,
) -> Result<T> {
    let memory = Arc::new(Memory::new_from_elf(elf_file)?);
    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(Arc::new(compute_key));

    let mut proc = FheComputer::new(&enc, &eval);

    let prog = memory
        .get_function_entry(program_name)
        .ok_or(Error::ElfSymbolNotFound(program_name.to_string()))?;

    proc.run_program(prog, &memory, arguments)
}

#[cfg(test)]
mod tests {
    use std::borrow::Borrow;

    use crate::ArgsBuilder;

    use super::*;
    use parasol_runtime::{
        Encryption,
        fluent::UInt,
        test_utils::{get_compute_key_128, get_secret_keys_128},
    };

    const CMUX_ELF: &[u8] = include_bytes!("../tests/test_data/cmux");

    #[test]
    fn test_run_program() {
        let compute_key = get_compute_key_128();
        let compute_key: &ComputeKey = compute_key.borrow();

        let enc = Encryption::default();
        let sk = get_secret_keys_128();

        let arguments = ArgsBuilder::new()
            .arg(UInt::<8, _>::encrypt_secret(42, &enc, &sk))
            .arg(UInt::<8, _>::encrypt_secret(54, &enc, &sk))
            .arg(UInt::<8, _>::encrypt_secret(11, &enc, &sk))
            .return_value::<UInt<8, _>>();

        let result = run_program(compute_key.clone(), CMUX_ELF, "cmux", arguments).unwrap();

        assert_eq!(result.decrypt(&enc, &sk), 54);
    }
}
