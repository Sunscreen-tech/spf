use num::Complex;
use serde::{Deserialize, Serialize};

use crate::{
    GlweDef, GlweDimension, OverlaySize, RadixCount, RadixDecomposition,
    dst::{NoWrapper, dst_allocate},
    entities::{DstIterator, DstIteratorMut, GlweKeyswitchKeyFftRef},
};

dst! {
    /// FFT versions of keys used for evaluating automorphisms on [`GlweCiphertext`](crate::entities::GlweCiphertext)s. Typically used
    /// to compute [`trace`](crate::ops::automorphisms::trace)
    AutomorphismKeyFft,
    AutomorphismKeyFftRef,
    NoWrapper,
    (Clone, Debug, Serialize, Deserialize),
    ()
}

impl OverlaySize for AutomorphismKeyFftRef<Complex<f64>> {
    type Inputs = (GlweDimension, RadixCount);

    fn size(t: Self::Inputs) -> usize {
        GlweKeyswitchKeyFftRef::<Complex<f64>>::size(t) * t.0.polynomial_degree.0.ilog2() as usize
    }
}

impl AutomorphismKeyFft<Complex<f64>> {
    /// Allocate a new [`AutomorphismKeyFft`] for the given parameters.
    pub fn new(glwe: &GlweDef, radix: &RadixDecomposition) -> Self {
        let len = AutomorphismKeyFftRef::<Complex<f64>>::size((glwe.dim, radix.count));

        Self {
            data: dst_allocate(len),
        }
    }
}

impl AutomorphismKeyFftRef<Complex<f64>> {
    /// Create an iterator over the contained
    /// [`GlweKeyswitchKey`](crate::entities::GlweKeyswitchKey)s.
    pub fn keyswitch_keys(
        &self,
        glwe: &GlweDef,
        radix: &RadixDecomposition,
    ) -> DstIterator<'_, GlweKeyswitchKeyFftRef<Complex<f64>>> {
        DstIterator::new(
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
    ) -> DstIteratorMut<'_, GlweKeyswitchKeyFftRef<Complex<f64>>> {
        DstIteratorMut::new(
            &mut self.data,
            GlweKeyswitchKeyFftRef::<Complex<f64>>::size((glwe.dim, radix.count)),
        )
    }

    /// Retrieve the keyswitch key for automorphism with power d.
    ///
    /// The automorphism keys are stored for d = [N, N/2, N/4, ..., 4, 2] where
    /// N is the polynomial degree.
    ///
    /// # Arguments
    /// * `d` - The power of 2 for the automorphism (d - 1 must be a power of 2 in range [1, N-1])
    /// * `glwe` - GLWE parameters containing dimension information
    /// * `radix` - Radix decomposition parameters
    ///
    /// # Panics
    /// Panics if:
    /// * `d - 1` is not a power of 2
    /// * `d < 2` or `d > N` where N is the polynomial degree
    pub fn keyswitch_key_at(
        &self,
        d: usize,
        glwe: &GlweDef,
        radix: &RadixDecomposition,
    ) -> &GlweKeyswitchKeyFftRef<Complex<f64>> {
        let n = glwe.dim.polynomial_degree.0;

        assert!(d >= 2, "d must be at least 2, got {d}");
        assert!(
            (d - 1).is_power_of_two(),
            "d - 1 must be a power of 2, got d = {d}"
        );
        assert!(d <= (n + 1), "d must be at most {n}, got {d}");

        // Convert d to index: index = log(N) - log(d - 1)
        let log_n = n.ilog2();
        let log_d_minus_1 = (d - 1).ilog2();
        let index = (log_n - log_d_minus_1) as usize;

        self.keyswitch_keys(glwe, radix)
            .nth(index)
            .expect("index out of bounds")
    }
}
