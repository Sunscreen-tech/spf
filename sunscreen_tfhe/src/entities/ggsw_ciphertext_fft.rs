use aligned_vec::avec;
use num::Complex;
use serde::{Deserialize, Serialize};

use crate::{
    GlweDef, GlweDimension, RadixCount, RadixDecomposition, TorusOps,
    dst::{AsMutSlice, AsSlice, NoWrapper, OverlaySize, dst_allocate},
    entities::{DstIterator, DstIteratorMut, GgswCiphertextRef},
    scratch::SIMD_ALIGN,
};

use super::GlevCiphertextFftRef;

dst! {
    /// The FFT variant of a GGSW ciphertext. See
    /// [`GgswCiphertext`](crate::entities::GgswCiphertext) for more details.
    GgswCiphertextFft,
    GgswCiphertextFftRef,
    NoWrapper,
    (Clone, Debug, Serialize, Deserialize),
    ()
}

impl OverlaySize for GgswCiphertextFftRef<Complex<f64>> {
    type Inputs = (GlweDimension, RadixCount);

    fn size(t: Self::Inputs) -> usize {
        GlevCiphertextFftRef::<Complex<f64>>::size(t) * (t.0.size.0 + 1)
    }
}

impl GgswCiphertextFft<Complex<f64>> {
    /// Creates a new GGSW ciphertext with FFT representation.
    pub fn new(params: &GlweDef, radix: &RadixDecomposition) -> GgswCiphertextFft<Complex<f64>> {
        let len = GgswCiphertextFftRef::size((params.dim, radix.count));

        GgswCiphertextFft {
            data: dst_allocate(len),
        }
    }
}

impl GgswCiphertextFftRef<Complex<f64>> {
    /// Returns an iterator over the rows of the GGSW ciphertext, which are
    /// [GlevCiphertextFft](crate::entities::GlevCiphertextFft)s.
    pub fn rows(
        &self,
        params: &GlweDef,
        radix: &RadixDecomposition,
    ) -> DstIterator<'_, GlevCiphertextFftRef<Complex<f64>>> {
        let stride = GlevCiphertextFftRef::<Complex<f64>>::size((params.dim, radix.count));

        DstIterator::new(self.as_slice(), stride)
    }

    /// Returns a mutable iterator over the rows of the GGSW ciphertext, which are
    /// [GlevCiphertextFft](crate::entities::GlevCiphertextFft)s.
    pub fn rows_mut(
        &mut self,
        params: &GlweDef,
        radix: &RadixDecomposition,
    ) -> DstIteratorMut<'_, GlevCiphertextFftRef<Complex<f64>>> {
        let stride = GlevCiphertextFftRef::<Complex<f64>>::size((params.dim, radix.count));

        DstIteratorMut::new(self.as_mut_slice(), stride)
    }

    /// Computes the inverse FFT of the GGSW ciphertexts and stores computation
    /// in `result`.
    pub fn ifft<S: TorusOps>(
        &self,
        result: &mut GgswCiphertextRef<S>,
        params: &GlweDef,
        radix: &RadixDecomposition,
    ) {
        for (s, r) in self.rows(params, radix).zip(result.rows_mut(params, radix)) {
            s.ifft(r, params);
        }
    }

    /// Create a new trivial GGSW ciphertext encrypting zero from an existing
    /// ciphertext.
    pub fn trivial_zero_from_existing(&self) -> GgswCiphertextFft<Complex<f64>> {
        let len = self.data.len();

        GgswCiphertextFft {
            data: avec![[SIMD_ALIGN]| Complex::from(<f64 as num::Zero>::zero()); len],
        }
    }
}
