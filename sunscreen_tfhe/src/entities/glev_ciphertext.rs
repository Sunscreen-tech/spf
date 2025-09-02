use aligned_vec::avec;
use num::Complex;
use serde::{Deserialize, Serialize};

use crate::{
    dst::{dst_allocate, dst_from_iter, OverlaySize}, entities::{DstIterator, DstIteratorMut}, scratch::SIMD_ALIGN, GlweDef, GlweDimension, RadixCount, RadixDecomposition, Torus, TorusOps
};

use super::{GlevCiphertextFftRef, GlweCiphertextRef};

dst! {
    /// A GLev ciphertext. For the FFT variant, see
    /// [`GlevCiphertextFft`](crate::entities::GlevCiphertextFft).
    GlevCiphertext,
    GlevCiphertextRef,
    Torus,
    (Clone, Debug, Serialize, Deserialize),
    (TorusOps,)
}

impl<S> OverlaySize for GlevCiphertextRef<S>
where
    S: TorusOps,
{
    type Inputs = (GlweDimension, RadixCount);

    fn size(t: Self::Inputs) -> usize {
        GlweCiphertextRef::<S>::size(t.0) * t.1.0
    }
}

impl<S> GlevCiphertext<S>
where
    S: TorusOps,
{
    /// Create a new zero GLev ciphertext with the given parameters.
    pub fn new(params: &GlweDef, radix: &RadixDecomposition) -> Self {
        let elems = GlevCiphertextRef::<S>::size((params.dim, radix.count));

        Self {
            data: dst_allocate(elems),
        }
    }
}

impl<S> GlevCiphertextRef<S>
where
    S: TorusOps,
{
    /// Returns an iterator over the rows of the GLEV ciphertext, which are
    /// [`GlweCiphertext`](crate::entities::GlweCiphertext)s.
    pub fn glwe_ciphertexts(&self, params: &GlweDef) -> DstIterator<'_, GlweCiphertextRef<S>> {
        DstIterator::new(&self.data, GlweCiphertextRef::<S>::size(params.dim))
    }

    /// Returns a mutable iterator over the rows of the GLEV ciphertext, which are
    /// [`GlweCiphertext](crate::entities::GlweCiphertext)s.
    pub fn glwe_ciphertexts_mut(
        &mut self,
        params: &GlweDef,
    ) -> DstIteratorMut<'_, GlweCiphertextRef<S>> {
        DstIteratorMut::new(&mut self.data, GlweCiphertextRef::<S>::size(params.dim))
    }

    /// Compute the FFT of each of the GLWE ciphertexts in the GLEV ciphertext.
    /// The result is stored in `result`.
    pub fn fft(&self, result: &mut GlevCiphertextFftRef<Complex<f64>>, params: &GlweDef) {
        for (i, fft) in self
            .glwe_ciphertexts(params)
            .zip(result.glwe_ciphertexts_mut(params))
        {
            i.fft(fft, params);
        }
    }

    /// Create a new trivial GLev ciphertext encrypting zero from an existing
    /// ciphertext.
    pub fn trivial_zero_from_existing(&self) -> GlevCiphertext<S> {
        let len = self.data.len();

        GlevCiphertext {
            data: dst_from_iter(std::iter::repeat_n(
                Torus::from(<S as num::Zero>::zero()),
                len,
            )),
        }
    }
}
