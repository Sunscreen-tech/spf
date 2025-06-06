use serde::{Deserialize, Serialize};
use sunscreen_math::Zero;

use crate::{
    GlweDef, GlweDimension, OverlaySize, RadixCount, RadixDecomposition, Torus, TorusOps,
    entities::{GlweKeyswitchKeyIterator, GlweKeyswitchKeyIteratorMut, GlweKeyswitchKeyRef},
};

dst! {
    /// Keys used for evaluating automorphisms on [`GlweCiphertext`](crate::entities::GlweCiphertext)s. Typically used
    /// to compute [`homomorphic_trace`]
    AutomorphismKey,
    AutmorphismKeyRef,
    Torus,
    (Clone, Debug, Serialize, Deserialize),
    (TorusOps)
}

impl<S: TorusOps> OverlaySize for AutmorphismKeyRef<S> {
    type Inputs = (GlweDimension, RadixCount);

    fn size(t: Self::Inputs) -> usize {
        GlweKeyswitchKeyRef::<S>::size(t) * t.0.polynomial_degree.0.ilog2() as usize
    }
}

impl<S: TorusOps> AutomorphismKey<S> {
    /// Allocate a new [`AutomorphismKey`] for the given parameters.
    pub fn new(glwe: &GlweDef, radix: &RadixDecomposition) -> Self {
        let len = AutmorphismKeyRef::<S>::size((glwe.dim, radix.count));

        Self {
            data: avec![Torus::zero(); len],
        }
    }
}

impl<S: TorusOps> AutmorphismKeyRef<S> {
    /// Create an iterator over the contained [`GlweKeyswitchKeyRef`]s.
    pub fn keyswitch_keys(
        &self,
        glwe: &GlweDef,
        radix: &RadixDecomposition,
    ) -> GlweKeyswitchKeyIterator<S> {
        GlweKeyswitchKeyIterator::new(
            &self.data,
            GlweKeyswitchKeyRef::<S>::size((glwe.dim, radix.count)),
        )
    }

    /// Create a mutable iterator over the contained [`GlweKeyswitchKeyRef`]s.
    pub fn keyswitch_keys_mut(
        &mut self,
        glwe: &GlweDef,
        radix: &RadixDecomposition,
    ) -> GlweKeyswitchKeyIteratorMut<S> {
        GlweKeyswitchKeyIteratorMut::new(
            &mut self.data,
            GlweKeyswitchKeyRef::<S>::size((glwe.dim, radix.count)),
        )
    }
}
