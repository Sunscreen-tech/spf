use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

use parasol_runtime::{ComputeKey, SecretKey};
use serde::{Deserialize, Serialize};

/// Generate the keys. In practice these are the only commands a developer needs
/// to run to generate keys and run FHE programs. The rest of this file is to
/// cache the keys to disk to save some compute time when running the Parasol
/// CPU multiple times.
fn generate_keys() -> (SecretKey, ComputeKey) {
    let secret_key = SecretKey::generate_with_default_params();
    let compute_key = ComputeKey::generate_with_default_params(&secret_key);
    (secret_key, compute_key)
}

/// Find the `target `directory. Used to cache the generated keys.
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
pub fn load_or_generate_keys(params_name: &str) -> std::io::Result<(SecretKey, ComputeKey)> {
    let target_dir = find_target_dir().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "Could not find target directory")
    })?;
    let keys_dir = target_dir.join("keys").join(params_name);
    fs::create_dir_all(&keys_dir)?;

    let secret_key_path = keys_dir.join("secret_key.bin");
    let compute_key_path = keys_dir.join("compute_key.bin");

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
        let (secret_key, compute_key) = generate_keys();
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
