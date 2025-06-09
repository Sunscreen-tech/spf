use num::{Complex, Zero};
use serde::{Deserialize, Serialize};

use crate::{
    GlweDef, GlweDimension, OverlaySize, RadixCount, RadixDecomposition,
    dst::NoWrapper,
    entities::{
        GlweKeyswitchKeyFftIterator, GlweKeyswitchKeyFftIteratorMut, GlweKeyswitchKeyFftRef,
    },
};

dst! {
    /// FFT versions of keys used for evaluating automorphisms on [`GlweCiphertext`](crate::entities::GlweCiphertext)s. Typically used
    /// to compute [`trace`](crate::ops::automorphisms::trace)
    AutomorphismKeyFft,
    AutmorphismKeyFftRef,
    NoWrapper,
    (Clone, Debug, Serialize, Deserialize),
    ()
}

impl OverlaySize for AutmorphismKeyFftRef<Complex<f64>> {
    type Inputs = (GlweDimension, RadixCount);

    fn size(t: Self::Inputs) -> usize {
        GlweKeyswitchKeyFftRef::<Complex<f64>>::size(t) * t.0.polynomial_degree.0.ilog2() as usize
    }
}

impl AutomorphismKeyFft<Complex<f64>> {
    /// Allocate a new [`AutomorphismKeyFft`] for the given parameters.
    pub fn new(glwe: &GlweDef, radix: &RadixDecomposition) -> Self {
        let len = AutmorphismKeyFftRef::<Complex<f64>>::size((glwe.dim, radix.count));

        Self {
            data: avec![Complex::zero(); len],
        }
    }
}

impl AutmorphismKeyFftRef<Complex<f64>> {
    /// Create an iterator over the contained
    /// [`GlweKeyswitchKey`](crate::entities::GlweKeyswitchKey)s.
    pub fn keyswitch_keys(
        &self,
        glwe: &GlweDef,
        radix: &RadixDecomposition,
    ) -> GlweKeyswitchKeyFftIterator<Complex<f64>> {
        GlweKeyswitchKeyFftIterator::new(
            &self.data,
            GlweKeyswitchKeyFftRef::<Complex<f64>>::size((glwe.dim, radix.count)),
        )
    }

    /// Create a mutable iterator over the contained
    /// [`GlweKeyswitchKey`](crate::entities::GlweKeyswitchKey)s.
    pub fn keyswitch_keys_mut(
        &mut self,
        glwe: &GlweDef,
        radix: &RadixDecomposition,
    ) -> GlweKeyswitchKeyFftIteratorMut<Complex<f64>> {
        GlweKeyswitchKeyFftIteratorMut::new(
            &mut self.data,
            GlweKeyswitchKeyFftRef::<Complex<f64>>::size((glwe.dim, radix.count)),
        )
    }
}
