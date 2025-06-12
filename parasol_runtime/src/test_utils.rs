use std::sync::{Arc, Mutex, OnceLock, mpsc::Receiver};

use crate::{
    ComputeKey, ComputeKeyNonFft, DEFAULT_128, Encryption, Evaluation, SecretKey, CircuitProcessor,
    crypto::PublicKey, params::DEFAULT_80,
};

static SECRET_KEYS_80: OnceLock<Arc<SecretKey>> = OnceLock::new();
static COMPUTE_KEYS_80: OnceLock<Arc<ComputeKey>> = OnceLock::new();

static SECRET_KEYS_128: OnceLock<Arc<SecretKey>> = OnceLock::new();
static COMPUTE_KEYS_128: OnceLock<Arc<ComputeKey>> = OnceLock::new();
static PUBLIC_KEYS_128: OnceLock<Arc<PublicKey>> = OnceLock::new();

pub fn get_secret_keys_80() -> Arc<SecretKey> {
    SECRET_KEYS_80
        .get_or_init(|| Arc::new(SecretKey::generate(&DEFAULT_80)))
        .clone()
}

pub fn get_compute_key_80() -> Arc<ComputeKey> {
    COMPUTE_KEYS_80
        .get_or_init(|| {
            Arc::new(
                ComputeKeyNonFft::generate(&get_secret_keys_80(), &DEFAULT_80).fft(&DEFAULT_80),
            )
        })
        .clone()
}

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

pub fn get_encryption_80() -> Encryption {
    Encryption { params: DEFAULT_80 }
}

pub fn get_encryption_128() -> Encryption {
    Encryption {
        params: DEFAULT_128,
    }
}

pub fn get_evaluation_80() -> Evaluation {
    Evaluation::new(get_compute_key_80(), &DEFAULT_80, &get_encryption_80())
}

pub fn make_uproc_80() -> (Mutex<CircuitProcessor>, Receiver<()>) {
    let enc = get_encryption_80();
    let eval = Evaluation::new(get_compute_key_80(), &DEFAULT_80, &enc);

    let proc = CircuitProcessor::new(16384, None, &eval, &enc);

    (Mutex::new(proc.0), proc.1)
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

pub fn make_uproc_with_flow_control_len_80(
    flow_control_len: usize,
) -> (Mutex<CircuitProcessor>, Receiver<()>) {
    let enc = get_encryption_80();
    let eval = Evaluation::new(get_compute_key_80(), &DEFAULT_80, &enc);

    let proc = CircuitProcessor::new(flow_control_len, None, &eval, &enc);

    (Mutex::new(proc.0), proc.1)
}
