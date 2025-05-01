// use parasol_cpu::{Buffer, run_program};
// use parasol_runtime::Encryption;
// use std::time::Instant;

// mod generate_keys;
// use generate_keys::load_or_generate_keys;

// // Embed the compiled Parasol add program into a constant.
// const FHE_FILE: &[u8] = include_bytes!("../data/add.a");

// fn main() {
//     println!("Running with {} threads", rayon::current_num_threads());

//     // Load or generate keys. Note that they only need to be generated once. In
//     // an actual application you would want to be careful to keep the secret key
//     // secure.
//     let (secret_key, compute_key) =
//         load_or_generate_keys("default-params").expect("Failed to load or generate keys");

//     // Define the values we want to add. The sizes of the values'
//     // sizes must match the values' sizes defined in the
//     // Parasol C program!
//     let a = 2u8;
//     let b = 7u8;

//     // To pass arguments into the Parasol C program, we must convert
//     // them to `Buffer`s. Note that we must provide an output
//     // buffer as well!
//     let arguments =
//         [a, b, 0u8].map(|x| Buffer::cipher_from_value(&x, &Encryption::default(), &secret_key));

//     // Run the program.
//     let now = Instant::now();
//     let (gas, encrypted_result) = run_program(compute_key.clone(), FHE_FILE, "add", &arguments, 200_000).unwrap();
//     let elapsed = now.elapsed();
//     println!("Time to run the program: {:?}", elapsed);

//     // Decrypt the result. Note that we have to choose the index
//     // to decrypt from all the arguments passed to the C function;
//     // since the result is written out to the third argument of
//     // the `add` function in C, we specify that index here.
//     let result = encrypted_result[2]
//         .cipher_try_into_value::<u8>(&Encryption::default(), &secret_key)
//         .unwrap();
//     println!("Encrypted {a} + {b} = {result}, using {gas} gas");
// }

fn main() {}
