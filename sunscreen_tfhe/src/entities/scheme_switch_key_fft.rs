use num::Complex;
use serde::{Deserialize, Serialize};

use crate::{
    GlweDef, GlweDimension, RadixCount, RadixDecomposition, TorusOps,
    dst::{AsMutSlice, AsSlice, NoWrapper, OverlaySize, dst_allocate},
    entities::{DstIterator, DstIteratorMut, SchemeSwitchKeyRef},
};

use super::{
    GlevCiphertextFftRef, GlweCiphertextFftRef, get_linear_index, triangular_number_entries,
};

dst! {
    /// The FFT variant of a scheme switch key. See
    /// [`SchemeSwitchKey`](crate::entities::SchemeSwitchKey) for more details.
    SchemeSwitchKeyFft,
    SchemeSwitchKeyFftRef,
    NoWrapper,
    (Clone, Debug, Serialize, Deserialize),
    ()
}

impl OverlaySize for SchemeSwitchKeyFftRef<Complex<f64>> {
    // GLWE, Radix
    type Inputs = (GlweDimension, RadixCount);

    fn size(t: Self::Inputs) -> usize {
        // A scheme switch key is a collection of GLEVs encrypting the secret
        // key polynomials multiplied by each other.
        let number_polynomials = t.0.size.0;
        let radix_count = t.1.0;
        let number_key_combinations = triangular_number_entries(number_polynomials);
        let glwe_encryption_size = GlweCiphertextFftRef::size(t.0);

        let glev_size = glwe_encryption_size * radix_count;

        glev_size * number_key_combinations
    }
}

impl SchemeSwitchKeyFft<Complex<f64>> {
    /// Creates a new scheme switch key with FFT representation.
    pub fn new(params: &GlweDef, radix: &RadixDecomposition) -> SchemeSwitchKeyFft<Complex<f64>> {
        let len = SchemeSwitchKeyFftRef::size((params.dim, radix.count));

        SchemeSwitchKeyFft {
            data: dst_allocate(len),
        }
    }
}

impl SchemeSwitchKeyFftRef<Complex<f64>> {
    /// Returns an iterator over the components of the scheme switch key
    /// components, which are
    /// [`GlevCiphertextFft`](crate::entities::GlevCiphertextFft)s. Note that
    /// this order will be the order of the secret key polynomials as if they
    /// were laid out in an upper triangular matrix. For example, for a GLWE
    /// size of 2, the third GLev returned will contain the message of sk_1 *
    /// sk_1 (indexed from zero) Note that this order will be the order of the
    /// secret key polynomials as if they were laid out in an upper triangular
    /// matrix.
    pub fn glev_ciphertexts(
        &self,
        params: &GlweDef,
        radix: &RadixDecomposition,
    ) -> DstIterator<'_, GlevCiphertextFftRef<Complex<f64>>> {
        let stride = GlevCiphertextFftRef::<Complex<f64>>::size((params.dim, radix.count));

        DstIterator::new(self.as_slice(), stride)
    }

    /// Returns a mutable iterator over the components of the scheme switch key
    /// components, which are
    /// [`GlevCiphertextFft`](crate::entities::GlevCiphertextFft)s. Note that this
    /// order will be the order of the secret key polynomials as if they were
    /// laid out in an upper triangular matrix. For example, for a GLWE size of
    /// 2, the third GLev returned will contain the message of sk_1 * sk_1
    /// (indexed from zero) Note that this order will be the order of the secret
    /// key polynomials as if they were laid out in an upper triangular matrix.
    pub fn glev_ciphertexts_mut(
        &mut self,
        params: &GlweDef,
        radix: &RadixDecomposition,
    ) -> DstIteratorMut<'_, GlevCiphertextFftRef<Complex<f64>>> {
        let stride = GlevCiphertextFftRef::<Complex<f64>>::size((params.dim, radix.count));

        DstIteratorMut::new(self.as_mut_slice(), stride)
    }

    /// Gets the GLev ciphertext at the given tuple index (i,j) representing the
    /// entry for s_i * s_j
    ///
    /// # Arguments
    /// * `i` - First index in the upper triangular matrix
    /// * `j` - Second index in the upper triangular matrix
    /// * `params` - GLWE parameters containing dimension information
    /// * `radix` - Radix decomposition parameters
    ///
    /// # Panics
    /// Panics if either index is >= the number of polynomials in the GLWE dimension
    pub fn get_glev_at_index(
        &self,
        i: usize,
        j: usize,
        params: &GlweDef,
        radix: &RadixDecomposition,
    ) -> &GlevCiphertextFftRef<Complex<f64>> {
        let n = params.dim.size.0;
        let linear_idx = get_linear_index(i, j, n);

        self.glev_ciphertexts(params, radix)
            .nth(linear_idx)
            .expect("Index out of bounds")
    }

    /// Gets a mutable reference to the GLEV ciphertext at the given tuple index (i,j)
    ///
    /// # Arguments
    /// * `i` - First index in the upper triangular matrix
    /// * `j` - Second index in the upper triangular matrix
    /// * `params` - GLWE parameters containing dimension information
    /// * `radix` - Radix decomposition parameters
    ///
    /// # Panics
    /// Panics if either index is >= the number of polynomials in the GLWE
    /// dimension
    pub fn get_glev_at_index_mut(
        &mut self,
        i: usize,
        j: usize,
        params: &GlweDef,
        radix: &RadixDecomposition,
    ) -> &GlevCiphertextFftRef<Complex<f64>> {
        let n = params.dim.size.0;
        let linear_idx = get_linear_index(i, j, n);

        self.glev_ciphertexts_mut(params, radix)
            .nth(linear_idx)
            .expect("Index out of bounds")
    }

    /// Computes the inverse FFT of the GLev ciphertexts and stores computation
    /// in `result`.
    pub fn ifft<S: TorusOps>(
        &self,
        result: &mut SchemeSwitchKeyRef<S>,
        params: &GlweDef,
        radix: &RadixDecomposition,
    ) {
        for (s, r) in self
            .glev_ciphertexts(params, radix)
            .zip(result.glev_ciphertexts_mut(params, radix))
        {
            s.ifft(r, params);
        }
    }
}
