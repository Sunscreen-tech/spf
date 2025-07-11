use serde::{Deserialize, Serialize};
use sunscreen_math::Zero;

use crate::{
    GlweDef, GlweDimension, PlaintextBits, Torus, TorusOps,
    dst::{FromMutSlice, FromSlice, OverlaySize},
    entities::PolynomialRef,
    ops::{bootstrapping::generate_lut, encryption::trivially_encrypt_glwe_ciphertext},
    scratch::allocate_scratch_ref,
};

use super::GlweCiphertextRef;

dst! {
    /// Lookup table for a univariate function used during
    /// [`programmable_bootstrap_univariate`](crate::ops::bootstrapping::programmable_bootstrap_univariate)
    /// and [`circuit_bootstrap_via_trace_and_scheme_switch`](crate::ops::bootstrapping::circuit_bootstrap_via_trace_and_scheme_switch).
    UnivariateLookupTable,
    UnivariateLookupTableRef,
    Torus,
    (Clone, Debug, Serialize, Deserialize),
    (TorusOps)
}

impl<S: TorusOps> OverlaySize for UnivariateLookupTableRef<S> {
    type Inputs = GlweDimension;

    fn size(t: Self::Inputs) -> usize {
        GlweCiphertextRef::<S>::size(t)
    }
}

impl<S: TorusOps> UnivariateLookupTable<S> {
    /// Creates a trivially encrypted lookup table that computes a single function `map`.
    ///
    /// # Remarks
    /// The result of this can be used with
    /// [`programmable_bootstrap_univariate`](crate::ops::bootstrapping::programmable_bootstrap_univariate).
    pub fn trivial_from_fn<F>(map: F, glwe: &GlweDef, plaintext_bits: PlaintextBits) -> Self
    where
        F: Fn(u64) -> u64,
    {
        let mut lut = UnivariateLookupTable {
            data: avec![Torus::zero(); UnivariateLookupTableRef::<S>::size(glwe.dim)],
        };

        lut.fill_trivial_from_fns(&[map], glwe, plaintext_bits);

        lut
    }

    /// Creates a trivially encrypted lookup table that computes multiple functions
    /// given by `maps`.
    ///
    /// # Remarks
    /// The result of this should be used with
    /// [`generalized_programmable_bootstrap`](crate::ops::bootstrapping::generalized_programmable_bootstrap).
    pub fn trivivial_multifunctional<F>(
        maps: &[F],
        glwe: &GlweDef,
        plaintext_bits: PlaintextBits,
    ) -> Self
    where
        F: Fn(u64) -> u64,
    {
        assert!(maps.len() > 1);

        let mut lut = UnivariateLookupTable {
            data: avec![Torus::zero(); UnivariateLookupTableRef::<S>::size(glwe.dim)],
        };

        lut.fill_trivial_from_fns(maps, glwe, plaintext_bits);

        lut
    }
}

impl<S: TorusOps> UnivariateLookupTableRef<S> {
    /// Return the underlying GLWE representation of a lookup table.
    pub fn glwe(&self) -> &GlweCiphertextRef<S> {
        GlweCiphertextRef::from_slice(&self.data)
    }

    /// Return a mutable representation of the underlying GLWE representation of
    /// a lookup table.
    pub fn glwe_mut(&mut self) -> &mut GlweCiphertextRef<S> {
        GlweCiphertextRef::from_mut_slice(&mut self.data)
    }

    /// Generates a look up table filled with the values from the provided map,
    /// and trivially encrypts the lookup table.
    pub fn fill_trivial_from_fns<F: Fn(u64) -> u64>(
        &mut self,
        maps: &[F],
        glwe: &GlweDef,
        plaintext_bits: PlaintextBits,
    ) {
        allocate_scratch_ref!(poly, PolynomialRef<Torus<S>>, (glwe.dim.polynomial_degree));

        generate_lut(poly, maps, glwe, plaintext_bits);

        trivially_encrypt_glwe_ciphertext(self.glwe_mut(), poly, glwe);
    }

    /// Creates a lookup table filled with the same value at every entry.
    pub fn fill_with_constant(&mut self, val: S, glwe: &GlweDef, plaintext_bits: PlaintextBits) {
        self.clear();
        for o in self.glwe_mut().b_mut(glwe).coeffs_mut() {
            *o = Torus::encode(val, plaintext_bits);
        }
    }
}
