use num::{Complex, Zero};
use serde::{Deserialize, Serialize};

use crate::{
    GlweDef, GlweDimension, RadixCount, RadixDecomposition, TorusOps,
    dst::{NoWrapper, OverlaySize},
    entities::GlweKeyswitchKey,
};

use super::{GlevCiphertextFftIterator, GlevCiphertextFftIteratorMut, GlevCiphertextFftRef};

// TODO: This GLWE keyswitch only works for switching to a new key with the same
// parameter. Copy what is above but changed for polynomials to enable
// converting to a different key parameter set.
dst! {
    /// An FFT'd GLWE keyswitch key used to switch a ciphertext from one key to another.
    /// See [`module`](crate::ops::keyswitch) documentation for more details.
    GlweKeyswitchKeyFft,
    GlweKeyswitchKeyFftRef,
    NoWrapper,
    (Clone, Debug, Serialize, Deserialize),
    ()
}
dst_iter! { GlweKeyswitchKeyFftIterator, GlweKeyswitchKeyFftIteratorMut, ParallelGlweKeyswitchKeyFftIterator, ParallelGlweKeyswitchKeyFftIteratorMut, NoWrapper, GlweKeyswitchKeyFftRef, ()}

impl OverlaySize for GlweKeyswitchKeyFftRef<Complex<f64>> {
    type Inputs = (GlweDimension, RadixCount);

    fn size(t: Self::Inputs) -> usize {
        GlevCiphertextFftRef::<Complex<f64>>::size(t) * (t.0.size.0)
    }
}

impl GlweKeyswitchKeyFft<Complex<f64>> {
    /// Creates a new GLWE keyswitch key. This enables switching to a new key as
    /// well as switching from the `original_params` that define the first key
    /// to the `new_params` that define the second key.
    pub fn new(params: &GlweDef, radix: &RadixDecomposition) -> Self {
        // TODO: Shouldn't this function take 2 GlweDefs?
        // Ryan: to whoever wrote this, yes, see the above todo next to the dst.
        let elems = GlweKeyswitchKeyFftRef::<Complex<f64>>::size((params.dim, radix.count));

        Self {
            data: avec![Complex::zero(); elems],
        }
    }
}

impl GlweKeyswitchKeyFftRef<Complex<f64>> {
    /// Returns an iterator over the rows of the GLWE keyswitch key, which are
    /// [`GlevCiphertext`](crate::entities::GlevCiphertext)s.
    pub fn rows(
        &self,
        params: &GlweDef,
        radix: &RadixDecomposition,
    ) -> GlevCiphertextFftIterator<Complex<f64>> {
        let stride = GlevCiphertextFftRef::<Complex<f64>>::size((params.dim, radix.count));

        GlevCiphertextFftIterator::new(&self.data, stride)
    }

    /// Returns a mutable iterator over the rows of the GLWE keyswitch key, which are
    /// [`GlevCiphertext`](crate::entities::GlevCiphertext)s.
    pub fn rows_mut(
        &mut self,
        params: &GlweDef,
        radix: &RadixDecomposition,
    ) -> GlevCiphertextFftIteratorMut<Complex<f64>> {
        let stride = GlevCiphertextFftRef::<Complex<f64>>::size((params.dim, radix.count));

        GlevCiphertextFftIteratorMut::new(&mut self.data, stride)
    }

    /// Takes the IFFT of these FFT'd keys and writes the result into the given [`GlweKeyswitchKey`].
    pub fn ifft<S>(
        &self,
        output: &mut GlweKeyswitchKey<S>,
        glwe: &GlweDef,
        radix: &RadixDecomposition,
    ) where
        S: TorusOps,
    {
        for (o, i) in output.rows_mut(glwe, radix).zip(self.rows(glwe, radix)) {
            i.ifft(o, glwe);
        }
    }
}
