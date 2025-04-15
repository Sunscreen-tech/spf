use parasol_cpu::{Buffer, run_program};
use parasol_runtime::{ComputeKey, Encryption, SecretKey};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Instant;

// Embed the compiled Parasol add program into a constant.
const FHE_FILE: &[u8] = include_bytes!("../data/add.a");

fn main() {
    println!("Running with {} threads", rayon::current_num_threads());

    // Load or generate keys. We cache the keys in the target directory, since
    // they only need to be generated once. In an actual application you would
    // want to be careful to keep the secret key secure.
    let (secret_key, compute_key) =
        load_or_generate_keys("default-params").expect("Failed to load or generate keys");

    // Define the values we want to add. The sizes of the values'
    // sizes must match the values' sizes defined in the
    // Parasol C program!
    let a = 2u8;
    let b = 7u8;

    // To pass arguments into the Parasol C program, we must convert
    // them to `Buffer`s. Note that we must provide an output
    // buffer as well!
    let arguments =
        [a, b, 0u8].map(|x| Buffer::cipher_from_value(&x, &Encryption::default(), &secret_key));

    // Run the program.
    let now = Instant::now();
    let encrypted_result = run_program(compute_key.clone(), FHE_FILE, "add", &arguments).unwrap();
    let elapsed = now.elapsed();
    println!("Time to run the program: {:?}", elapsed);

    // Decrypt the result. Note that we have to choose the index
    // to decrypt from all the arguments passed to the C function;
    // since the result is written out to the third argument of
    // the `add` function in C, we specify that index here.
    let result = encrypted_result[2]
        .cipher_try_into_value::<u8>(&Encryption::default(), &secret_key)
        .unwrap();
    println!("Encrypted {a} + {b} = {result}");
}

/// Find the `target `directory.
fn find_target_dir() -> Option<PathBuf> {
    let mut current_dir = std::env::current_exe().ok()?;
    while current_dir.pop() {
        if current_dir.ends_with("target") {
            return Some(current_dir);
        }
    }
    None
}

/// Loads up the secret and compute keys from disk, or generates new ones if
/// they don't exist.
///
/// Arguments:
///     params_name: The name of the parameters to use.
///
/// Returns:
///     A tuple of the secret and compute keys.
fn load_or_generate_keys(params_name: &str) -> std::io::Result<(SecretKey, ComputeKey)> {
    let target_dir = find_target_dir().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "Could not find target directory")
    })?;
    let keys_dir = target_dir.join("keys").join(params_name);
    fs::create_dir_all(&keys_dir)?;

    let secret_key_path = keys_dir.join(format!("secret_key_{}.bin", params_name));
    let compute_key_path = keys_dir.join(format!("compute_key_{}.bin", params_name));

    if secret_key_path.exists() && compute_key_path.exists() {
        // Load keys from disk.
        println!("Loading keys from disk");
        println!("secret key path: {}", secret_key_path.display());
        println!("compute key path: {}", compute_key_path.display());
        let secret_key = load_key(&secret_key_path)?;
        let compute_key = load_key(&compute_key_path)?;
        Ok((secret_key, compute_key))
    } else {
        // Generate new keys
        println!("Generating new keys. This only needs to be done once.");
        let secret_key = SecretKey::generate_with_default_params();
        let compute_key = ComputeKey::generate_with_default_params(&secret_key);

        // Serialize the keys to disk
        println!("Writing keys to disk");
        println!("secret key path: {}", secret_key_path.display());
        println!("compute key path: {}", compute_key_path.display());
        serialize_key(&secret_key, &secret_key_path)?;
        serialize_key(&compute_key, &compute_key_path)?;

        Ok((secret_key, compute_key))
    }
}

/// Loads a key from disk.
///
/// Arguments:
///     path: The path to the key file.
///
/// Returns:
///     The deserialized key.
fn load_key<T: for<'de> Deserialize<'de>>(path: &PathBuf) -> std::io::Result<T> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let key = bincode::deserialize(&buffer).expect("Failed to deserialize key");
    Ok(key)
}

/// Serializes a key to disk.
///
/// Arguments:
///     key: The key to serialize.
///     path: The path to the key file.
///
/// Returns:
///     Ok(()) if the key was successfully serialized, Err otherwise.
fn serialize_key<T: Serialize>(key: &T, path: &PathBuf) -> std::io::Result<()> {
    let bytes = bincode::serialize(key).expect("Failed to serialize key");
    let mut file = File::create(path)?;
    file.write_all(&bytes)?;
    Ok(())
}
