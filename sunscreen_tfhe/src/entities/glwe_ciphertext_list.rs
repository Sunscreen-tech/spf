use serde::{Deserialize, Serialize};
use sunscreen_math::Zero;

use crate::{
    GlweDef, GlweDimension, Torus, TorusOps,
    dst::{AsMutSlice, AsSlice, OverlaySize},
    entities::{GlweCiphertextIterator, GlweCiphertextIteratorMut, GlweCiphertextRef},
};

dst! {
    /// A list of LWE ciphertexts. Used during
    /// [`circuit_bootstrap`](crate::ops::bootstrapping::circuit_bootstrap).
    GlweCiphertextList,
    GlweCiphertextListRef,
    Torus,
    (Clone, Debug, Serialize, Deserialize),
    (TorusOps)
}

impl<S: TorusOps> OverlaySize for GlweCiphertextListRef<S> {
    type Inputs = (GlweDimension, usize);

    #[inline(always)]
    fn size(t: Self::Inputs) -> usize {
        GlweCiphertextRef::<S>::size(t.0) * t.1
    }
}

impl<S: TorusOps> GlweCiphertextList<S> {
    /// Create a new zero [GlweCiphertextList] with the given parameters.
    ///
    /// This data structure represents is a list of LWE ciphertexts, used for
    /// [`circuit_bootstrap`](crate::ops::bootstrapping::circuit_bootstrap).
    pub fn new(lwe: &GlweDef, count: usize) -> Self {
        Self {
            data: avec![Torus::zero(); GlweCiphertextListRef::<S>::size((lwe.dim, count))],
        }
    }
}

impl<S: TorusOps> GlweCiphertextListRef<S> {
    /// Iterate over the GLWE ciphertexts in the list.
    pub fn ciphertexts(&self, lwe: &GlweDef) -> GlweCiphertextIterator<S> {
        GlweCiphertextIterator::new(self.as_slice(), GlweCiphertextRef::<S>::size(lwe.dim))
    }

    /// Iterate over the GLWE ciphertexts in the list mutably.
    pub fn ciphertexts_mut(&mut self, lwe: &GlweDef) -> GlweCiphertextIteratorMut<S> {
        GlweCiphertextIteratorMut::new(self.as_mut_slice(), GlweCiphertextRef::<S>::size(lwe.dim))
    }
}
