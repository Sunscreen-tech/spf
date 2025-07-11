use num::{Complex, Zero};
use serde::{Deserialize, Serialize};

use crate::{
    GlweDef, GlweDimension, RadixCount, RadixDecomposition, Torus, TorusOps, dst::OverlaySize,
    entities::GlweKeyswitchKeyFftRef,
};

use super::{GlevCiphertextIterator, GlevCiphertextIteratorMut, GlevCiphertextRef};

// TODO: This GLWE keyswitch only works for switching to a new key with the same
// parameter. Copy what is above but changed for polynomials to enable
// converting to a different key parameter set.
dst! {
    /// A GLWE keyswitch key used to switch a ciphertext from one key to another.
    /// See [`module`](crate::ops::keyswitch) documentation for more details.
    GlweKeyswitchKey,
    GlweKeyswitchKeyRef,
    Torus,
    (Clone, Debug, Serialize, Deserialize),
    (TorusOps,)
}
dst_iter! { GlweKeyswitchKeyIterator, GlweKeyswitchKeyIteratorMut, ParallelGlweKeyswitchKeyIterator, ParallelGlweKeyswitchKeyIteratorMut, Torus, GlweKeyswitchKeyRef, (TorusOps,)}

impl<S> OverlaySize for GlweKeyswitchKeyRef<S>
where
    S: TorusOps,
{
    type Inputs = (GlweDimension, RadixCount);

    fn size(t: Self::Inputs) -> usize {
        GlevCiphertextRef::<S>::size(t) * (t.0.size.0)
    }
}

impl<S> GlweKeyswitchKey<S>
where
    S: TorusOps,
{
    /// Creates a new GLWE keyswitch key. This enables switching to a new key as
    /// well as switching from the `original_params` that define the first key
    /// to the `new_params` that define the second key.
    pub fn new(params: &GlweDef, radix: &RadixDecomposition) -> Self {
        // TODO: Shouldn't this function take 2 GlweDefs?
        // Ryan: to whoever wrote this, yes, see the above todo next to the dst.
        let elems = GlweKeyswitchKeyRef::<S>::size((params.dim, radix.count));

        Self {
            data: avec![Torus::zero(); elems],
        }
    }
}

impl<S> GlweKeyswitchKeyRef<S>
where
    S: TorusOps,
{
    /// Returns an iterator over the rows of the GLWE keyswitch key, which are
    /// [`GlevCiphertext`](crate::entities::GlevCiphertext)s.
    pub fn rows(&self, params: &GlweDef, radix: &RadixDecomposition) -> GlevCiphertextIterator<S> {
        let stride = GlevCiphertextRef::<S>::size((params.dim, radix.count));

        GlevCiphertextIterator::new(&self.data, stride)
    }

    /// Returns a mutable iterator over the rows of the GLWE keyswitch key, which are
    /// [`GlevCiphertext`](crate::entities::GlevCiphertext)s.
    pub fn rows_mut(
        &mut self,
        params: &GlweDef,
        radix: &RadixDecomposition,
    ) -> GlevCiphertextIteratorMut<S> {
        let stride = GlevCiphertextRef::<S>::size((params.dim, radix.count));

        GlevCiphertextIteratorMut::new(&mut self.data, stride)
    }

    /// Takes the FFT of these keyswitch keys and write the result into the given
    /// [`GlweKeyswitchKeyFft`](crate::entities::GlweKeyswitchKeyFft).
    pub fn fft(
        &self,
        output: &mut GlweKeyswitchKeyFftRef<Complex<f64>>,
        glwe: &GlweDef,
        radix: &RadixDecomposition,
    ) {
        for (o, i) in output.rows_mut(glwe, radix).zip(self.rows(glwe, radix)) {
            i.fft(o, glwe);
        }
    }
}
