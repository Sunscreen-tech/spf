use std::sync::{Arc, Mutex, OnceLock, mpsc::Receiver};

use crate::{
    CircuitProcessor, ComputeKey, ComputeKeyNonFft, DEFAULT_128, Encryption, Evaluation, SecretKey,
    crypto::PublicKey,
};

static SECRET_KEYS_128: OnceLock<Arc<SecretKey>> = OnceLock::new();
static COMPUTE_KEYS_128: OnceLock<Arc<ComputeKey>> = OnceLock::new();
static PUBLIC_KEYS_128: OnceLock<Arc<PublicKey>> = OnceLock::new();

pub fn get_secret_keys_128() -> Arc<SecretKey> {
    SECRET_KEYS_128
        .get_or_init(|| Arc::new(SecretKey::generate(&DEFAULT_128)))
        .clone()
}

pub fn get_compute_key_128() -> Arc<ComputeKey> {
    COMPUTE_KEYS_128
        .get_or_init(|| {
            Arc::new(
                ComputeKeyNonFft::generate(&get_secret_keys_128(), &DEFAULT_128).fft(&DEFAULT_128),
            )
        })
        .clone()
}

pub fn get_public_key_128() -> Arc<PublicKey> {
    PUBLIC_KEYS_128
        .get_or_init(|| Arc::new(PublicKey::generate(&DEFAULT_128, &get_secret_keys_128())))
        .clone()
}

pub fn get_encryption_128() -> Encryption {
    Encryption {
        params: DEFAULT_128,
    }
}

pub fn get_evaluation_128() -> Evaluation {
    Evaluation::new(get_compute_key_128(), &DEFAULT_128, &get_encryption_128())
}

pub fn make_uproc_128() -> (Mutex<CircuitProcessor>, Receiver<()>) {
    let enc = get_encryption_128();
    let eval = Evaluation::new(get_compute_key_128(), &DEFAULT_128, &enc);

    let proc = CircuitProcessor::new(16384, None, &eval, &enc);

    (Mutex::new(proc.0), proc.1)
}
