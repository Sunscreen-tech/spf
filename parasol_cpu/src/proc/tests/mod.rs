mod add;
mod and;
mod bitshift;
mod branch;
mod casting;
mod cmux;
mod comparisons;
mod input_output;
mod load_store;
mod mul;
mod neg;
mod not;
mod or;
mod sub;
mod xor;

use parasol_runtime::{Encryption, DEFAULT_80};

use crate::Buffer;
use parasol_runtime::test_utils::get_secret_keys_80;

#[test]
fn ciphertext_buffers_contain_multiple_of_8_bits() {
    let enc = Encryption::new(&DEFAULT_80);
    let buffer = Buffer::cipher_from_value(&1u8, &enc, &get_secret_keys_80());

    assert_eq!(buffer.try_ciphertext().unwrap().len(), 8);

    let buffer = Buffer::cipher_from_value(&vec![0u8, 1, 2], &enc, &get_secret_keys_80());
    assert_eq!(buffer.try_ciphertext().unwrap().len(), 24);
}
