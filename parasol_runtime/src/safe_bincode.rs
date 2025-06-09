use bincode::{DefaultOptions, Options};
use serde::Deserialize;

use crate::{Params, Result};

/// Get the expected size of a type for safe bincode deserialization.
pub trait GetSize {
    /// The expected size under the given [`Params`].
    fn get_size(params: &Params) -> usize;

    /// Check if the given object is valid under the given [`Params`].
    fn check_is_valid(&self, params: &Params) -> Result<()>;
}

/// Safely deserialize the given buffer given a type
pub fn deserialize<'a, T: GetSize + Deserialize<'a>>(data: &'a [u8], params: &Params) -> Result<T> {
    let options = DefaultOptions::new()
        .with_limit(T::get_size(params) as u64)
        .with_fixint_encoding()
        .allow_trailing_bytes();

    let mut deserializer = bincode::Deserializer::from_slice(data, options);
    let result = T::deserialize(&mut deserializer)?;
    result.check_is_valid(params)?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::{
        ComputeKey, ComputeKeyNonFft, DEFAULT_80, DEFAULT_128, Encryption, L0LweCiphertext,
        L1GlevCiphertext, L1GlweCiphertext, L1LweCiphertext, PublicKey, SecretKey,
        test_utils::{
            get_compute_key_128, get_secret_keys_128,
        },
    };

    use super::*;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[test]
    fn can_safe_deserialize_ciphertexts() {
        let enc = Encryption::new(&DEFAULT_128);

        let ser = bincode::serialize(&enc.allocate_lwe_l0()).unwrap();
        deserialize::<L0LweCiphertext>(&ser, &DEFAULT_128).unwrap();
        let ser = bincode::serialize(&enc.allocate_lwe_l1()).unwrap();
        deserialize::<L1LweCiphertext>(&ser, &DEFAULT_128).unwrap();
        let ser = bincode::serialize(&enc.allocate_glwe_l1()).unwrap();
        deserialize::<L1GlweCiphertext>(&ser, &DEFAULT_128).unwrap();
        let ser = bincode::serialize(&enc.allocate_glev_l1()).unwrap();
        deserialize::<L1GlevCiphertext>(&ser, &DEFAULT_128).unwrap();
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[test]
    fn rejects_malformed_serialized_ciphertext() {
        macro_rules! case {
            ($ct_ty:ty, $val: expr) => {
                // Malformed length
                let ser = vec![
                    253, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1, 0x2, 0x3, 0x4,
                ];

                let res = deserialize::<$ct_ty>(&ser, &DEFAULT_128);

                assert!(res.is_err());

                let ser = bincode::serialize::<$ct_ty>($val).unwrap();
                let res = deserialize::<$ct_ty>(&ser, &DEFAULT_80);

                assert!(res.is_err());
            };
        }

        let enc = Encryption::new(&DEFAULT_128);

        case!(L0LweCiphertext, &enc.trivial_lwe_l0_one());
        case!(L1LweCiphertext, &enc.trivial_lwe_l1_one());
        case!(L1GlweCiphertext, &enc.trivial_glwe_l1_one());
        case!(L1GlevCiphertext, &enc.trivial_glev_l1_one());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[test]
    fn can_safe_deserialize_keys() {
        let sk = get_secret_keys_128();
        let ser = bincode::serialize(&sk).unwrap();
        deserialize::<SecretKey>(&ser, &DEFAULT_128).unwrap();

        let compute = ComputeKeyNonFft::generate(&sk, &DEFAULT_128);
        let ser = bincode::serialize(&compute).unwrap();
        deserialize::<ComputeKeyNonFft>(&ser, &DEFAULT_128).unwrap();

        let pk = PublicKey::generate(&DEFAULT_128, &sk);
        let ser = bincode::serialize(&pk).unwrap();
        deserialize::<PublicKey>(&ser, &DEFAULT_128).unwrap();

        let compute = get_compute_key_128();
        let ser = bincode::serialize(&compute).unwrap();
        deserialize::<ComputeKey>(&ser, &DEFAULT_128).unwrap();
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[test]
    fn rejects_malformed_keys() {
        macro_rules! case {
            ($key_ty:ty) => {
                // Malformed length
                let ser = vec![
                    253, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1, 0x2, 0x3, 0x4,
                ];

                let res = deserialize::<$key_ty>(&ser, &DEFAULT_128);

                assert!(res.is_err());
            };
        }

        case!(PublicKey);
        case!(SecretKey);
        case!(ComputeKeyNonFft);

        let sk = get_secret_keys_128();

        let ser = bincode::serialize(&sk).unwrap();
        let result = deserialize::<SecretKey>(&ser, &DEFAULT_80);

        assert!(result.is_err());

        let ser = bincode::serialize(&ComputeKeyNonFft::generate(&sk, &DEFAULT_128)).unwrap();
        let result = deserialize::<ComputeKeyNonFft>(&ser, &DEFAULT_80);

        assert!(result.is_err());

        let pk = PublicKey::generate(&DEFAULT_128, &sk);
        let ser = bincode::serialize(&pk).unwrap();
        let result = deserialize::<PublicKey>(&ser, &DEFAULT_80);

        assert!(result.is_err());
    }
}
