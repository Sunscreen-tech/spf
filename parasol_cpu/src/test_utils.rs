use std::sync::{Arc, OnceLock};

use parasol_runtime::{
    test_utils::{
        get_compute_key_128, get_compute_key_80, get_secret_keys_128, get_secret_keys_80,
    },
    Encryption, Evaluation, SecretKey, DEFAULT_128, DEFAULT_80,
};
use rayon::{ThreadPool, ThreadPoolBuilder};
use sunscreen_tfhe::entities::Polynomial;

use crate::{Buffer, FheComputer, IntoBytes};

pub fn poly_one() -> Arc<Polynomial<u64>> {
    static ONE: OnceLock<Arc<Polynomial<u64>>> = OnceLock::new();

    ONE.get_or_init(|| {
        let mut coeffs = vec![0; 1024];
        coeffs[0] = 1;
        Arc::new(Polynomial::new(&coeffs))
    })
    .clone()
}

pub fn get_thread_pool() -> Arc<ThreadPool> {
    static THREAD_POOL: OnceLock<Arc<ThreadPool>> = OnceLock::new();

    THREAD_POOL
        .get_or_init(|| {
            Arc::new(
                ThreadPoolBuilder::new()
                    .thread_name(|x| format!("Fhe worker {x}"))
                    .build()
                    .unwrap(),
            )
        })
        .clone()
}

/// Create a computer with the default encryption and evaluation.
pub fn make_computer_80() -> (FheComputer, Encryption) {
    let compute_key = get_compute_key_80();
    let enc = Encryption::new(&DEFAULT_80);
    let eval = Evaluation::new(compute_key, &DEFAULT_80, &enc);

    (
        FheComputer::new_with_threadpool(&enc, &eval, get_thread_pool()),
        enc,
    )
}

pub fn make_computer_128() -> (FheComputer, Encryption) {
    let compute_key = get_compute_key_128();
    let enc = Encryption::new(&DEFAULT_128);
    let eval = Evaluation::new(compute_key, &DEFAULT_128, &enc);

    (
        FheComputer::new_with_threadpool(&enc, &eval, get_thread_pool()),
        enc,
    )
}

/// Create a buffer from a value, either encrypted or plaintext, using a secret key.
pub fn buffer_from_value_sk<T>(
    value: T,
    enc: &Encryption,
    secret_key: &SecretKey,
    encrypted_computation: bool,
) -> Buffer
where
    T: IntoBytes + Copy,
{
    if encrypted_computation {
        Buffer::cipher_from_value(&value, enc, secret_key)
    } else {
        Buffer::plain_from_value(&value)
    }
}

/// Create a buffer from a value, either encrypted or plaintext, using the global secret key.
pub fn buffer_from_value_80<T>(value: T, enc: &Encryption, encrypted_computation: bool) -> Buffer
where
    T: IntoBytes + Copy,
{
    buffer_from_value_sk(
        value,
        enc,
        get_secret_keys_80().as_ref(),
        encrypted_computation,
    )
}

/// Create a buffer from a value, either encrypted or plaintext, using the global secret key.
pub fn buffer_from_value_128<T>(value: T, enc: &Encryption, encrypted_computation: bool) -> Buffer
where
    T: IntoBytes + Copy,
{
    buffer_from_value_sk(
        value,
        enc,
        get_secret_keys_128().as_ref(),
        encrypted_computation,
    )
}

/// Read the result from a buffer, either encrypted or plaintext, using a secret key.
pub fn read_result_sk<T>(
    buffer: &Buffer,
    enc: &Encryption,
    secret_key: &SecretKey,
    encrypted_computation: bool,
) -> T
where
    T: IntoBytes + Copy,
{
    if encrypted_computation {
        buffer.cipher_try_into_value::<T>(enc, secret_key).unwrap()
    } else {
        buffer.plain_try_into_value::<T>().unwrap()
    }
}

/// Read the result from a buffer, either encrypted or plaintext, using the global secret key.
pub fn read_result<T>(buffer: &Buffer, enc: &Encryption, encrypted_computation: bool) -> T
where
    T: IntoBytes + Copy,
{
    read_result_sk(
        buffer,
        enc,
        get_secret_keys_80().as_ref(),
        encrypted_computation,
    )
}
