use num::Complex;
use serde::{Deserialize, Serialize};

use crate::{
    GlweDef, GlweDimension, RadixCount, RadixDecomposition, TorusOps,
    dst::{NoWrapper, OverlaySize, dst_allocate},
    entities::{DstIterator, DstIteratorMut},
};

use super::{GlevCiphertextRef, GlweCiphertextFftRef};

dst! {
    /// The FFT variant of a GLEV ciphertext. See
    /// [GlevCiphertext](crate::entities::GlevCiphertext) for more details.
    GlevCiphertextFft,
    GlevCiphertextFftRef,
    NoWrapper,
    (Clone, Debug, Serialize, Deserialize),
    ()
}

impl GlevCiphertextFft<Complex<f64>> {
    /// Create a new zero GLev ciphertext with the given parameters.
    pub fn new(params: &GlweDef, radix: &RadixDecomposition) -> Self {
        let elems = GlevCiphertextFftRef::<Complex<f64>>::size((params.dim, radix.count));

        Self {
            data: dst_allocate(elems),
        }
    }
}

impl OverlaySize for GlevCiphertextFftRef<Complex<f64>> {
    type Inputs = (GlweDimension, RadixCount);

    fn size(t: Self::Inputs) -> usize {
        GlweCiphertextFftRef::<Complex<f64>>::size(t.0) * t.1.0
    }
}

impl GlevCiphertextFftRef<Complex<f64>> {
    /// Returns an iterator over the rows of the GLEV ciphertext, which are
    /// [`GlweCiphertextFft`](crate::entities::GlweCiphertextFft)s.
    pub fn glwe_ciphertexts(
        &self,
        params: &GlweDef,
    ) -> DstIterator<'_, GlweCiphertextFftRef<Complex<f64>>> {
        DstIterator::new(
            &self.data,
            GlweCiphertextFftRef::<Complex<f64>>::size(params.dim),
        )
    }

    /// Returns a mutable iterator over the rows of the GLEV ciphertext, which are
    /// [`GlweCiphertextFft`](crate::entities::GlweCiphertextFft)s.
    pub fn glwe_ciphertexts_mut(
        &mut self,
        params: &GlweDef,
    ) -> DstIteratorMut<'_, GlweCiphertextFftRef<Complex<f64>>> {
        DstIteratorMut::new(
            &mut self.data,
            GlweCiphertextFftRef::<Complex<f64>>::size(params.dim),
        )
    }

    /// Computes the inverse FFT of the GLEV ciphertexts and stores computation
    /// in `result`.
    pub fn ifft<S: TorusOps>(&self, result: &mut GlevCiphertextRef<S>, params: &GlweDef) {
        for (i, ifft) in self
            .glwe_ciphertexts(params)
            .zip(result.glwe_ciphertexts_mut(params))
        {
            i.ifft(ifft, params);
        }
    }
}
