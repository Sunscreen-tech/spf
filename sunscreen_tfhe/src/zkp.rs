use crate::{
    FGreco, GRECO_MODULUS, GlweDef, Torus,
    entities::{GlweCiphertext, GlweCiphertextRef, GlweSecretKey, GlweSecretKeyRef},
};

impl GlweSecretKeyRef<u64> {
    /// Create a copy of the secret key under the Greco field.
    pub fn to_greco(&self, params: &GlweDef) -> GlweSecretKey<FGreco> {
        let mut sk_greco = GlweSecretKey::insecure_zero(params);

        for (g, s) in sk_greco.s_mut(params).zip(self.s(params)) {
            for (g, s) in g.coeffs_mut().iter_mut().zip(s.coeffs().iter()) {
                *g = FGreco::from(*s);
            }
        }

        sk_greco
    }
}

impl GlweCiphertextRef<FGreco> {
    /// Modulus switch this ciphertext to 2**64
    pub fn to_u64(&self, params: &GlweDef) -> GlweCiphertext<u64> {
        let mut res = GlweCiphertext::new(params);

        for (a_greco, a_u64) in self.a(params).zip(res.a_mut(params)) {
            for (a_g, a_64) in a_greco.coeffs().iter().zip(a_u64.coeffs_mut().iter_mut()) {
                let a_g: u64 = a_g.inner().into();
                *a_64 = Torus::from((((a_g as u128) << 64) / GRECO_MODULUS as u128) as u64);
            }
        }

        for (b_g, b_64) in self
            .b(params)
            .coeffs()
            .iter()
            .zip(res.b_mut(params).coeffs_mut().iter_mut())
        {
            let b_g: u64 = b_g.inner().into();
            *b_64 = Torus::from((((b_g as u128) << 64) / GRECO_MODULUS as u128) as u64);
        }

        res
    }
}
