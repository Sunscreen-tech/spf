use parasol_runtime::{ComputeKey, Encryption, Evaluation, SecretKey};

// We know the server program takes three arguments: two input values and an
// output buffer.
type AddArguments = [parasol_cpu::Buffer; 3];

// The code the user will run
fn user_program<F>(compute_add_on_server: F)
where
    F: FnOnce(ComputeKey, Encryption, AddArguments) -> parasol_cpu::Buffer,
{
    // Generate a secret key for the user. The `DEFAULT_128` parameter is the
    // security level of the encryption. The higher the number, the more secure
    // the encryption, but the slower the operations.
    let secret_key = SecretKey::generate(&parasol_runtime::DEFAULT_128);

    // Generate the encryption parameters for the user
    let enc = Encryption::new(&parasol_runtime::DEFAULT_128);

    // Generate a server key for the user. These keys are used for operations
    // and do not give the server access to the data.
    let server_key = ComputeKey::generate(&secret_key, &parasol_runtime::DEFAULT_128);

    // Define the values we want to add. The sizes of the values must match the
    // size of the values defined in the C TFHE program!
    let a = 2u8;
    let b = 7u8;

    // To pass arguments into the TFHE C program, we must convert them to
    // `Buffer`s. Note that we must provide an output buffer as well!
    let arguments =
        [a, b, 0u8].map(|x| parasol_cpu::Buffer::cipher_from_value(&x, &enc, &secret_key));

    // Call the server using an remote procedure call (RPC) interface.
    let encrypted_result = compute_add_on_server(server_key, enc.clone(), arguments);

    // Decypt the result.
    let result = encrypted_result
        .cipher_try_into_value::<u8>(&enc, &secret_key)
        .unwrap();
    println!("Encrypted {a} + {b} = {result}");
}

// The code the server will run
use parasol_cpu::{FheApplication, FheComputer};
use std::sync::Arc;

// Define the path to the compiled TFHE add program.
const FHE_FILE: &[u8] = include_bytes!("../data/add.a");

fn server_program(
    server_key: ComputeKey,
    enc: Encryption,
    arguments: AddArguments,
) -> parasol_cpu::Buffer {
    // Generate a new FHE processor for the server
    let eval = Evaluation::new(Arc::new(server_key), &parasol_runtime::DEFAULT_128, &enc);
    let mut proc = FheComputer::new(&enc, &eval);

    // Load in the TFHE compiled file.
    let result = FheApplication::parse_elf(FHE_FILE).unwrap();

    // Get the specific function we want to run from the compiled file. Note
    // that the name "add" in the call to `get_program` has to match the name of
    // the function in the C file.
    let add = result.get_program(&"add".into()).unwrap();

    // Run the addition program with the provided encrypted arguments
    // (a, b, output).
    proc.run_program(add, &arguments).unwrap();

    // The output parameter is the last one, so we extract that value and return
    // it to the user.
    arguments[arguments.len() - 1].clone()
}

fn main() {
    user_program(server_program)
}
