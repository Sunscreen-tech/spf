use petgraph::stable_graph::NodeIndex;
use std::ops::Deref;

use bumpalo::Bump;

use crate::fluent::{CiphertextOps, DynamicGenericIntGraphNodes, Sign};

/// A collection of graph nodes with a constant size generic parameter, similar to [`DynamicGenericIntGraphNodes`]
/// and uses it as the internal representation
pub struct GenericIntGraphNodes<'a, const N: usize, T: CiphertextOps, U: Sign> {
    inner: DynamicGenericIntGraphNodes<'a, T, U>,
}

impl<'a, const N: usize, T: CiphertextOps, U: Sign> Deref for GenericIntGraphNodes<'a, N, T, U> {
    type Target = DynamicGenericIntGraphNodes<'a, T, U>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, const N: usize, T: CiphertextOps, U: Sign> From<GenericIntGraphNodes<'a, N, T, U>>
    for DynamicGenericIntGraphNodes<'a, T, U>
{
    fn from(value: GenericIntGraphNodes<'a, N, T, U>) -> DynamicGenericIntGraphNodes<'a, T, U> {
        value.inner
    }
}

impl<'a, const N: usize, T: CiphertextOps, U: Sign> From<DynamicGenericIntGraphNodes<'a, T, U>>
    for GenericIntGraphNodes<'a, N, T, U>
{
    fn from(value: DynamicGenericIntGraphNodes<'a, T, U>) -> Self {
        assert_eq!(value.bits.len(), N);

        Self { inner: value }
    }
}

impl<'a, const N: usize, T: CiphertextOps, U: Sign> GenericIntGraphNodes<'a, N, T, U> {
    pub(crate) fn from_nodes<I: ExactSizeIterator<Item = NodeIndex>>(
        iter: I,
        bump: &'a Bump,
    ) -> GenericIntGraphNodes<'a, N, T, U> {
        assert_eq!(iter.len(), N);

        Self {
            inner: DynamicGenericIntGraphNodes::from_nodes(iter, bump),
        }
    }
}
