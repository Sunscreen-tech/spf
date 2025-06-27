use std::sync::{Arc, OnceLock};

use parasol_runtime::{ComputeKey, SecretKey};

// TODO: Need to update compiler calling convention and recompile to
// fix these tests.
mod e2e_tests;

pub fn get_sk() -> &'static SecretKey {
    static SK: OnceLock<SecretKey> = OnceLock::new();

    SK.get_or_init(SecretKey::generate_with_default_params)
}

pub fn get_ck() -> Arc<ComputeKey> {
    static CK: OnceLock<Arc<ComputeKey>> = OnceLock::new();

    CK.get_or_init(|| Arc::new(ComputeKey::generate_with_default_params(get_sk())))
        .clone()
}
