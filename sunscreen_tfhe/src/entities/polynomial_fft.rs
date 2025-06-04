use num::Complex;

use crate::{
    FrequencyTransform, FromF64, NumBits, PolynomialDegree,
    dst::{AsMutSlice, AsSlice, NoWrapper, OverlaySize},
    fft::negacyclic::get_fft,
    scratch::allocate_scratch,
    simd::{self, VectorOps},
};

use super::PolynomialRef;

dst! {
    /// The FFT of a polynomial. See [`Polynomial`](crate::entities::Polynomial)
    /// for the non-FFT variant.
    PolynomialFft,
    PolynomialFftRef,
    NoWrapper,
    (Debug, Clone),
    ()
}
dst_iter!(
    PolynomialFftIterator,
    PolynomialFftIteratorMut,
    ParallelPolynomialFftIterator,
    ParallelPolynomialFftIteratorMut,
    NoWrapper,
    PolynomialFftRef,
    ()
);

impl<T> OverlaySize for PolynomialFftRef<T>
where
    T: Clone,
{
    type Inputs = PolynomialDegree;

    fn size(t: Self::Inputs) -> usize {
        t.0 / 2
    }
}

impl<T> PolynomialFft<T>
where
    T: Clone,
{
    /// Create a new polynomial with the given length in the fourier domain.
    pub fn new(data: &[T]) -> Self {
        Self {
            data: avec_from_slice!(data),
        }
    }
}

impl<T> PolynomialFftRef<T>
where
    T: Clone,
{
    /// Returns the coefficients of the polynomial in the fourier domain.
    pub fn coeffs(&self) -> &[T] {
        &self.data
    }

    /// Returns the mutable coefficients of the polynomial in the fourier domain.
    pub fn coeffs_mut(&mut self) -> &mut [T] {
        &mut self.data
    }

    /// Returns the number of coefficients in the polynomial.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the polynomial has no coefficients.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl PolynomialFftRef<Complex<f64>> {
    /// Compute the inverse FFT of the polynomial.
    pub fn ifft<T>(&self, poly: &mut PolynomialRef<T>)
    where
        T: Clone + FromF64 + NumBits + VectorOps,
    {
        assert!(self.len().is_power_of_two());
        assert_eq!(self.len() * 2, poly.len());

        let log_n = poly.len().ilog2() as usize;

        let fft = get_fft(log_n);

        let mut ifft = allocate_scratch::<f64>(poly.len());
        let ifft = ifft.as_mut_slice();

        fft.reverse(&self.data, ifft);

        T::vector_mod_pow2_q_f64(poly.coeffs_mut(), ifft, T::BITS as u64);
    }

    /// Computes the multiplication of two polynomials as `c += a * b`. This is
    /// more efficient than the naive method, and has a runtime of O(N). Note
    /// that performing the FFT and IFFT to get in and out of the fourier domain
    /// costs O(N log N).
    pub fn multiply_add(
        &mut self,
        a: &PolynomialFftRef<Complex<f64>>,
        b: &PolynomialFftRef<Complex<f64>>,
    ) {
        simd::complex_mad(self.as_mut_slice(), a.as_slice(), b.as_slice());
    }
}
