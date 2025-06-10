use serde::{Deserialize, Serialize};
use sunscreen_math::Zero;

use crate::{
    LweDef, LweDimension, Torus, TorusOps,
    dst::{AsMutSlice, AsSlice, OverlaySize},
};

use super::{LweCiphertextIterator, LweCiphertextIteratorMut, LweCiphertextRef};

dst! {
    /// A list of [`LweCiphertext`](crate::entities::LweCiphertext)s stored contiguously in memory.
    LweCiphertextList,
    LweCiphertextListRef,
    Torus,
    (Clone, Debug, Serialize, Deserialize),
    (TorusOps)
}

impl<S: TorusOps> OverlaySize for LweCiphertextListRef<S> {
    type Inputs = (LweDimension, usize);

    #[inline(always)]
    fn size(t: Self::Inputs) -> usize {
        LweCiphertextRef::<S>::size(t.0) * t.1
    }
}

impl<S: TorusOps> LweCiphertextList<S> {
    /// Create a new zero [LweCiphertextList] with the given parameters.
    ///
    /// # Remarks
    /// This data structure represents is a list of LWE ciphertexts, used internally
    /// during classic (and now deprecated) [`circuit_bootstrap_via_pfks`(crate::ops::bootstrapping::circuit_bootstrap_via_pfks).
    pub fn new(lwe: &LweDef, count: usize) -> Self {
        Self {
            data: avec![Torus::zero(); LweCiphertextListRef::<S>::size((lwe.dim, count))],
        }
    }
}

impl<S: TorusOps> LweCiphertextListRef<S> {
    /// Iterate over the LWE ciphertexts in the list.
    pub fn ciphertexts(&self, lwe: &LweDef) -> LweCiphertextIterator<S> {
        LweCiphertextIterator::new(self.as_slice(), LweCiphertextRef::<S>::size(lwe.dim))
    }

    /// Iterate over the LWE ciphertexts in the list mutably.
    pub fn ciphertexts_mut(&mut self, lwe: &LweDef) -> LweCiphertextIteratorMut<S> {
        LweCiphertextIteratorMut::new(self.as_mut_slice(), LweCiphertextRef::<S>::size(lwe.dim))
    }
}
