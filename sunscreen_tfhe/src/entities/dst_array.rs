use std::{
    borrow::{Borrow, BorrowMut},
    ops::{Deref, DerefMut},
};

use bytemuck::Pod;

use crate::{
    OverlaySize,
    dst::{
        Allocation, AsMutSlice, AsSlice, FromMutSlice, FromSlice, InnermostType, Len, dst_allocate,
    },
    entities::{DstIterator, DstIteratorMut, ParallelDstIterator, ParallelDstIteratorMut},
};

/// An array of objects that share a single allocation. Borrowing results in
/// a [`DstArrayRef`], which is an actual dynamic sized type.
/// one.
#[derive(Clone, PartialEq)]
pub struct DstArray<T>
where
    T: Deref,
    <T as Deref>::Target: InnermostType + OverlaySize,
    <<T as Deref>::Target as InnermostType>::Ty: Pod + PartialEq,
{
    data: Allocation<<<T as Deref>::Target as InnermostType>::Ty>,
}

impl<T> Len for DstArrayRef<T>
where
    T: InnermostType + OverlaySize + ToOwned + ?Sized,
    <T as InnermostType>::Ty: Pod + PartialEq,
{
    fn len(&self) -> usize {
        self.data.len()
    }
}

impl<T> OverlaySize for DstArrayRef<T>
where
    T: InnermostType + OverlaySize + ToOwned + ?Sized,
    <T as InnermostType>::Ty: Pod + PartialEq,
{
    type Inputs = (usize, <T as OverlaySize>::Inputs);

    fn size(t: Self::Inputs) -> usize {
        T::size(t.1) * t.0
    }
}

impl<T> DstArray<T>
where
    T: Deref,
    <T as Deref>::Target: InnermostType + OverlaySize,
    <<T as Deref>::Target as InnermostType>::Ty: Pod + PartialEq + Default,
{
    /// Create a new [`DstArray`].
    pub fn new(n: usize, size_params: <<T as Deref>::Target as OverlaySize>::Inputs) -> Self {
        let len = <<T as Deref>::Target as OverlaySize>::size(size_params);

        Self {
            data: dst_allocate(len * n),
        }
    }
}

impl<T> Deref for DstArray<T>
where
    T: Deref,
    <T as Deref>::Target: InnermostType + OverlaySize + ToOwned,
    <<T as Deref>::Target as InnermostType>::Ty: Pod + PartialEq,
{
    type Target = DstArrayRef<<T as Deref>::Target>;

    fn deref(&self) -> &Self::Target {
        DstArrayRef::from_slice(self.data.as_slice())
    }
}

impl<T> DerefMut for DstArray<T>
where
    T: Deref,
    <T as Deref>::Target: InnermostType + OverlaySize + ToOwned,
    <<T as Deref>::Target as InnermostType>::Ty: Pod + PartialEq,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        DstArrayRef::from_mut_slice(self.data.as_mut_slice())
    }
}

impl<T> Borrow<DstArrayRef<<T as Deref>::Target>> for DstArray<T>
where
    T: Deref,
    <T as Deref>::Target: InnermostType + OverlaySize + ToOwned,
    <<T as Deref>::Target as InnermostType>::Ty: Pod + PartialEq,
{
    fn borrow(&self) -> &DstArrayRef<<T as Deref>::Target> {
        DstArrayRef::from_slice(self.as_slice())
    }
}

impl<T> BorrowMut<DstArrayRef<<T as Deref>::Target>> for DstArray<T>
where
    T: Deref,
    <T as Deref>::Target: InnermostType + OverlaySize + ToOwned,
    <<T as Deref>::Target as InnermostType>::Ty: Pod + PartialEq,
{
    fn borrow_mut(&mut self) -> &mut DstArrayRef<<T as Deref>::Target> {
        DstArrayRef::from_mut_slice(self.as_mut_slice())
    }
}

impl<T> AsSlice<<<T as Deref>::Target as InnermostType>::Ty> for DstArray<T>
where
    T: Deref,
    <T as Deref>::Target: InnermostType + OverlaySize + ToOwned,
    <<T as Deref>::Target as InnermostType>::Ty: Pod + PartialEq,
{
    fn as_slice(&self) -> &[<<T as Deref>::Target as InnermostType>::Ty] {
        self.data.as_slice()
    }
}

impl<T> AsMutSlice<<<T as Deref>::Target as InnermostType>::Ty> for DstArray<T>
where
    T: Deref,
    <T as Deref>::Target: InnermostType + OverlaySize + ToOwned,
    <<T as Deref>::Target as InnermostType>::Ty: Pod + PartialEq,
{
    fn as_mut_slice(&mut self) -> &mut [<<T as Deref>::Target as InnermostType>::Ty] {
        self.data.as_mut_slice()
    }
}

/// A DST borrow of [`DstArray`].
#[repr(transparent)]
#[derive(PartialEq)]
pub struct DstArrayRef<T>
where
    T: InnermostType + OverlaySize + ToOwned + ?Sized,
    <T as InnermostType>::Ty: Pod + PartialEq,
{
    data: [<T as InnermostType>::Ty],
}

impl<T> FromSlice<<T as InnermostType>::Ty> for DstArrayRef<T>
where
    T: InnermostType + OverlaySize + ToOwned + ?Sized,
    <T as InnermostType>::Ty: Pod + PartialEq,
{
    fn from_slice(data: &[<T as InnermostType>::Ty]) -> &Self {
        unsafe { &*(data as *const [<T as InnermostType>::Ty] as *const DstArrayRef<T>) }
    }
}

impl<T> FromMutSlice<<T as InnermostType>::Ty> for DstArrayRef<T>
where
    T: InnermostType + OverlaySize + ToOwned + ?Sized,
    <T as InnermostType>::Ty: Pod + PartialEq,
{
    fn from_mut_slice(data: &mut [<T as InnermostType>::Ty]) -> &mut Self {
        unsafe { &mut *(data as *mut [<T as InnermostType>::Ty] as *mut DstArrayRef<T>) }
    }
}

impl<T> ToOwned for DstArrayRef<T>
where
    T: ToOwned + InnermostType + OverlaySize,
    <T as InnermostType>::Ty: Pod + PartialEq,
    <T as ToOwned>::Owned: Deref,
    <<T as ToOwned>::Owned as Deref>::Target: InnermostType + OverlaySize + ToOwned,
    <<<T as ToOwned>::Owned as Deref>::Target as InnermostType>::Ty: Pod + PartialEq + Default,
    DstArray<<T as ToOwned>::Owned>: Borrow<Self>,
{
    type Owned = DstArray<<T as ToOwned>::Owned>;

    fn to_owned(&self) -> Self::Owned {
        let mut cloned = dst_allocate(self.data.len());

        // These slice types are actually the same, but the compiler doesn't know
        // that ToOwned::Owned::Deref::Target is Self.
        cloned
            .as_mut_slice()
            .clone_from_slice(bytemuck::cast_slice(&self.data));

        DstArray { data: cloned }
    }
}

impl<T> DstArrayRef<T>
where
    T: InnermostType + OverlaySize + ToOwned + AsSlice<<T as InnermostType>::Ty> + ?Sized,
    <T as InnermostType>::Ty: Pod + PartialEq,
{
    /// Create an iterator that emits `&T`s contained in the DST
    pub fn iter(&self, size_info: <T as OverlaySize>::Inputs) -> DstIterator<T> {
        DstIterator::new(&self.data, T::size(size_info))
    }

    /// Create a mutable iterator that emits `&mut T`s contained in the DST
    pub fn iter_mut(&mut self, size_info: <T as OverlaySize>::Inputs) -> DstIteratorMut<T> {
        DstIteratorMut::new(&mut self.data, T::size(size_info))
    }
}

impl<T> DstArrayRef<T>
where
    T: InnermostType
        + OverlaySize
        + ToOwned
        + AsSlice<<T as InnermostType>::Ty>
        + Sync
        + Send
        + ?Sized,
    <T as InnermostType>::Ty: Pod + PartialEq,
{
    /// A parallel iterator over the elements in the array.
    pub fn par_iter(&self, size_info: <T as OverlaySize>::Inputs) -> ParallelDstIterator<T> {
        ParallelDstIterator::new(&self.data, T::size(size_info))
    }

    /// A mutable parallel iterator over the elements in the array.
    pub fn par_iter_mut(
        &mut self,
        size_info: <T as OverlaySize>::Inputs,
    ) -> ParallelDstIteratorMut<T> {
        ParallelDstIteratorMut::new(&mut self.data, T::size(size_info))
    }
}
