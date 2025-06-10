use num::Complex;
use serde::{Deserialize, Serialize};
use sunscreen_math::Zero;

use crate::{
    GlweDef, GlweDimension, OverlaySize, RadixCount, RadixDecomposition, Torus, TorusOps,
    entities::{
        AutomorphismKeyFft, GlweKeyswitchKeyIterator, GlweKeyswitchKeyIteratorMut,
        GlweKeyswitchKeyRef,
    },
};

dst! {
    /// Keys used for evaluating automorphisms on [`GlweCiphertext`](crate::entities::GlweCiphertext)s. Typically used
    /// to compute [`trace`](crate::ops::automorphisms::trace)
    AutomorphismKey,
    AutomorphismKeyRef,
    Torus,
    (Clone, Debug, Serialize, Deserialize),
    (TorusOps)
}

impl<S: TorusOps> OverlaySize for AutomorphismKeyRef<S> {
    type Inputs = (GlweDimension, RadixCount);

    fn size(t: Self::Inputs) -> usize {
        GlweKeyswitchKeyRef::<S>::size(t) * t.0.polynomial_degree.0.ilog2() as usize
    }
}

impl<S: TorusOps> AutomorphismKey<S> {
    /// Allocate a new [`AutomorphismKey`] for the given parameters.
    pub fn new(glwe: &GlweDef, radix: &RadixDecomposition) -> Self {
        let len = AutomorphismKeyRef::<S>::size((glwe.dim, radix.count));

        Self {
            data: avec![Torus::zero(); len],
        }
    }
}

impl<S: TorusOps> AutomorphismKeyRef<S> {
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

    /// Takes the fft of these keys and writes the result to `result`.
    pub fn fft(
        &self,
        result: &mut AutomorphismKeyFft<Complex<f64>>,
        glwe: &GlweDef,
        radix: &RadixDecomposition,
    ) {
        for (i, o) in self
            .keyswitch_keys(glwe, radix)
            .zip(result.keyswitch_keys_mut(glwe, radix))
        {
            i.fft(o, glwe, radix);
        }
    }
}
