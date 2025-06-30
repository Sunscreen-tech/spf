use parasol_cpu::{ArgsBuilder, run_program};
use parasol_runtime::{Encryption, fluent::UInt8};
use std::time::Instant;

mod generate_keys;
use generate_keys::load_or_generate_keys;

// Embed the compiled Parasol add program into a constant.
const FHE_FILE: &[u8] = include_bytes!("../data/add");

fn main() {
    println!("Running with {} threads", rayon::current_num_threads());

    // Load or generate keys. Note that they only need to be generated once. In
    // an actual application you would want to be careful to keep the secret key
    // secure.
    let (secret_key, compute_key) =
        load_or_generate_keys("default-params").expect("Failed to load or generate keys");

    // Define the values we want to add. The sizes of the values'
    // sizes must match the values' sizes defined in the
    // Parasol C program!
    let a = 2u8;
    let b = 7u8;

    // To pass arguments into the Parasol C program, we build the `Args`
    // with this `ArgsBuilder` to specify the input and return data types.
    // To use encrypted input we need an encryption instance
    let enc = Encryption::default();
    let args = ArgsBuilder::new()
        .arg(UInt8::encrypt_secret(a as u128, &enc, &secret_key))
        .arg(UInt8::encrypt_secret(b as u128, &enc, &secret_key))
        .return_value::<UInt8>();

    // Run the program.
    let now = Instant::now();
    let encrypted_result = run_program(compute_key.clone(), FHE_FILE, "add", args).unwrap();
    let elapsed = now.elapsed();
    println!("Time to run the program: {elapsed:?}");

    // Decrypt the result.
    let result = encrypted_result.decrypt(&enc, &secret_key);
    println!("Encrypted {a} + {b} = {result}");
}
