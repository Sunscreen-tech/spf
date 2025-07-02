use std::ops::Deref;

use crate::fluent::{
    CiphertextOps, PackedDynamicGenericIntGraphNode, PolynomialCiphertextOps, Sign,
};

/// FIXME
pub struct PackedGenericIntGraphNode<
    const N: usize,
    T: CiphertextOps + PolynomialCiphertextOps,
    U: Sign,
> {
    inner: PackedDynamicGenericIntGraphNode<T, U>,
}

impl<const N: usize, T: CiphertextOps + PolynomialCiphertextOps, U: Sign> Deref
    for PackedGenericIntGraphNode<N, T, U>
{
    type Target = PackedDynamicGenericIntGraphNode<T, U>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<const N: usize, T: CiphertextOps + PolynomialCiphertextOps, U: Sign>
    From<PackedGenericIntGraphNode<N, T, U>> for PackedDynamicGenericIntGraphNode<T, U>
{
    fn from(value: PackedGenericIntGraphNode<N, T, U>) -> PackedDynamicGenericIntGraphNode<T, U> {
        value.inner
    }
}

impl<const N: usize, T: CiphertextOps + PolynomialCiphertextOps, U: Sign>
    From<PackedDynamicGenericIntGraphNode<T, U>> for PackedGenericIntGraphNode<N, T, U>
{
    fn from(value: PackedDynamicGenericIntGraphNode<T, U>) -> Self {
        assert_eq!(value.bit_len as usize, N);

        Self { inner: value }
    }
}
