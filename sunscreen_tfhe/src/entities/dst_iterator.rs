use crate::dst::{AsSlice, FromMutSlice, FromSlice, InnermostType};

use std::iter::Iterator;

/// An iterator over a linear buffer containing dynamic sized types.
pub struct DstIterator<'a, T>
where
    T: InnermostType + ?Sized,
{
    data: &'a [<T as InnermostType>::Ty],
    stride: usize,
    front_idx: usize,
    back_idx: usize,
}

impl<'a, T> DstIterator<'a, T>
where
    T: InnermostType + AsSlice<<T as InnermostType>::Ty> + ?Sized,
{
    /// Create a new [`DstIterator`]
    pub fn new(data: &'a [<T as InnermostType>::Ty], stride: usize) -> Self {
        assert_eq!(data.len() % stride, 0);

        Self {
            data,
            stride,
            front_idx: 0,
            back_idx: data.len(),
        }
    }
}

impl<'a, T> std::iter::ExactSizeIterator for DstIterator<'a, T>
where
    T: 'a
        + InnermostType
        + AsSlice<<T as InnermostType>::Ty>
        + FromSlice<<T as InnermostType>::Ty>
        + ?Sized,
{
    #[inline(always)]
    fn len(&self) -> usize {
        self.data.len() / self.stride
    }
}

impl<'a, T> Iterator for DstIterator<'a, T>
where
    T: 'a
        + InnermostType
        + AsSlice<<T as InnermostType>::Ty>
        + FromSlice<<T as InnermostType>::Ty>
        + ?Sized,
{
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.front_idx == self.back_idx {
            return None;
        }

        let item = T::from_slice(&self.data[self.front_idx..self.front_idx + self.stride]);
        self.front_idx += self.stride;

        Some(item)
    }
}

impl<'a, T> DoubleEndedIterator for DstIterator<'a, T>
where
    T: 'a
        + InnermostType
        + AsSlice<<T as InnermostType>::Ty>
        + FromSlice<<T as InnermostType>::Ty>
        + ?Sized,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front_idx == self.back_idx {
            return None;
        }

        let idx_start = self.back_idx - self.stride;
        let item = T::from_slice(&self.data[idx_start..idx_start + self.stride]);
        self.back_idx -= self.stride;

        Some(item)
    }
}

/// A parallel iterator over a linear buffer containing dynamic sized types.
pub struct ParallelDstIterator<'a, T>
where
    T: Send + Sync + InnermostType + ?Sized,
{
    data: &'a [<T as InnermostType>::Ty],
    stride: usize,
    count: usize,
}

impl<'a, T> ParallelDstIterator<'a, T>
where
    T: Send + Sync + InnermostType + ?Sized,
{
    /// Create a new [`ParallelDstIterator`]
    pub fn new(data: &'a [<T as InnermostType>::Ty], stride: usize) -> Self {
        assert_eq!(data.len() % stride, 0);

        let count = data.len() / stride;

        Self {
            data,
            stride,
            count,
        }
    }
}

impl<'a, T> rayon::iter::plumbing::Producer for ParallelDstIterator<'a, T>
where
    T: 'a
        + InnermostType
        + AsSlice<<T as InnermostType>::Ty>
        + FromSlice<<T as InnermostType>::Ty>
        + Sync
        + Send
        + ?Sized,
    <T as InnermostType>::Ty: Sync + Send,
{
    type Item = &'a T;
    type IntoIter = DstIterator<'a, T>;

    fn split_at(self, index: usize) -> (Self, Self) {
        let len = <Self as rayon::iter::IndexedParallelIterator>::len(&self);

        let (left, right) = self.data.split_at(index * self.stride);

        let left = Self {
            data: left,
            stride: self.stride,
            count: index,
        };

        let right = Self {
            data: right,
            stride: self.stride,
            count: len - index,
        };

        (left, right)
    }

    fn into_iter(self) -> Self::IntoIter {
        DstIterator::new(self.data, self.stride)
    }
}

impl<'a, T> rayon::iter::ParallelIterator for ParallelDstIterator<'a, T>
where
    T: Send
        + 'a
        + Sync
        + InnermostType
        + AsSlice<<T as InnermostType>::Ty>
        + FromSlice<<T as InnermostType>::Ty>
        + ?Sized,
    <T as InnermostType>::Ty: Sync + Send,
{
    type Item = &'a T;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::UnindexedConsumer<Self::Item>,
    {
        rayon::iter::plumbing::bridge(self, consumer)
    }
}

impl<'a, T> rayon::iter::IndexedParallelIterator for ParallelDstIterator<'a, T>
where
    T: Send
        + 'a
        + Sync
        + InnermostType
        + AsSlice<<T as InnermostType>::Ty>
        + FromSlice<<T as InnermostType>::Ty>
        + ?Sized,
    <T as InnermostType>::Ty: Sync + Send,
{
    #[inline(always)]
    fn len(&self) -> usize {
        self.count
    }

    fn drive<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::Consumer<Self::Item>,
    {
        rayon::iter::plumbing::bridge(self, consumer)
    }

    fn with_producer<CB>(self, callback: CB) -> CB::Output
    where
        CB: rayon::iter::plumbing::ProducerCallback<Self::Item>,
    {
        callback.callback(self)
    }
}

/// A mutable iterator over a linear sequence of dynamic sized types.
pub struct DstIteratorMut<'a, T>
where
    T: InnermostType + ?Sized,
{
    start: *mut <T as InnermostType>::Ty,
    front: isize,
    back: isize,
    stride: isize,
    _phantom: std::marker::PhantomData<&'a T>,
}

impl<'a, T> DstIteratorMut<'a, T>
where
    T: InnermostType + ?Sized,
{
    /// Create a new iterator that emits references to the contained type
    /// by striding over the underlying data, mutably.
    pub fn new(data: &'a mut [<T as InnermostType>::Ty], stride: usize) -> Self {
        assert_eq!(data.len() % stride, 0);

        Self {
            start: data.as_mut_ptr(),
            front: 0,
            back: data.len() as isize,
            stride: stride as isize,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, T> Iterator for DstIteratorMut<'a, T>
where
    T: InnermostType + FromMutSlice<<T as InnermostType>::Ty> + ?Sized,
{
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }

        let slice = unsafe {
            let ptr = self.start.offset(self.front);
            std::slice::from_raw_parts_mut(ptr, self.stride as usize)
        };

        self.front += self.stride;

        Some(<T as FromMutSlice<<T as InnermostType>::Ty>>::from_mut_slice(slice))
    }
}

impl<'a, T> ExactSizeIterator for DstIteratorMut<'a, T>
where
    T: InnermostType + FromMutSlice<<T as InnermostType>::Ty> + ?Sized,
{
    #[inline(always)]
    fn len(&self) -> usize {
        ((self.back - self.front) / self.stride) as usize
    }
}

impl<'a, T> DoubleEndedIterator for DstIteratorMut<'a, T>
where
    T: InnermostType + FromMutSlice<<T as InnermostType>::Ty> + ?Sized,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }

        let slice = unsafe {
            let ptr = self.start.offset(self.back - self.stride);
            std::slice::from_raw_parts_mut(ptr, self.stride as usize)
        };

        self.back -= self.stride;

        Some(<T as FromMutSlice<<T as InnermostType>::Ty>>::from_mut_slice(slice))
    }
}

/// A parallel iterator over a linear sequence of dynamically sized types.
pub struct ParallelDstIteratorMut<'a, T>
where
    T: InnermostType + ?Sized,
{
    data: &'a mut [<T as InnermostType>::Ty],
    stride: usize,
    count: usize,
}

impl<'a, T> ParallelDstIteratorMut<'a, T>
where
    T: InnermostType + ?Sized,
{
    #[inline(always)]
    #[allow(unused)]
    /// Create a new mutable parallel iterator.
    pub fn new(data: &'a mut [<T as InnermostType>::Ty], stride: usize) -> Self {
        assert_eq!(data.len() % stride, 0);

        let count = data.len() / stride;

        Self {
            data,
            stride,
            count,
        }
    }
}

impl<'a, T> rayon::iter::plumbing::Producer for ParallelDstIteratorMut<'a, T>
where
    T: 'a + Send + Sync + InnermostType + FromMutSlice<<T as InnermostType>::Ty> + ?Sized,
    <T as InnermostType>::Ty: Sync + Send,
{
    type Item = &'a mut T;
    type IntoIter = DstIteratorMut<'a, T>;

    #[inline(always)]
    fn split_at(self, index: usize) -> (Self, Self) {
        let len = <Self as rayon::iter::IndexedParallelIterator>::len(&self);

        let (left, right) = self.data.split_at_mut(index * self.stride);

        let left = Self {
            data: left,
            stride: self.stride,
            count: index,
        };

        let right = Self {
            data: right,
            stride: self.stride,
            count: len - index,
        };

        (left, right)
    }

    #[inline(always)]
    fn into_iter(self) -> Self::IntoIter {
        DstIteratorMut::new(self.data, self.stride)
    }
}

impl<'a, T> rayon::iter::ParallelIterator for ParallelDstIteratorMut<'a, T>
where
    T: 'a + Send + Sync + InnermostType + FromMutSlice<<T as InnermostType>::Ty> + ?Sized,
    <T as InnermostType>::Ty: Sync + Send,
{
    type Item = &'a mut T;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::UnindexedConsumer<Self::Item>,
    {
        rayon::iter::plumbing::bridge(self, consumer)
    }
}

impl<'a, T> rayon::iter::IndexedParallelIterator for ParallelDstIteratorMut<'a, T>
where
    T: 'a + Send + Sync + InnermostType + FromMutSlice<<T as InnermostType>::Ty> + ?Sized,
    <T as InnermostType>::Ty: Sync + Send,
{
    #[inline(always)]
    fn len(&self) -> usize {
        self.count
    }

    fn drive<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::Consumer<Self::Item>,
    {
        rayon::iter::plumbing::bridge(self, consumer)
    }

    fn with_producer<CB>(self, callback: CB) -> CB::Output
    where
        CB: rayon::iter::plumbing::ProducerCallback<Self::Item>,
    {
        callback.callback(self)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::dst::{AsMutSlice, NoWrapper};

    use rayon::iter::{IndexedParallelIterator, ParallelIterator};

    dst! {
        Foo,
        FooRef,
        NoWrapper,
        (Clone, Debug),
        ()
    }

    #[test]
    fn can_iterate_over_dst_array() {
        let data = (0..30).collect::<Vec<_>>();

        for (i, x) in DstIterator::<FooRef<usize>>::new(&data, 3).enumerate() {
            assert_eq!(x.as_slice()[0], 3 * i);
            assert_eq!(x.as_slice()[1], 3 * i + 1);
            assert_eq!(x.as_slice()[2], 3 * i + 2);
        }
    }

    #[test]
    fn reverse_iterate() {
        let data = (0..30).rev().collect::<Vec<_>>();

        for (i, x) in DstIterator::<FooRef<usize>>::new(&data, 3)
            .rev()
            .enumerate()
        {
            assert_eq!(x.as_slice()[0], 3 * i + 2);
            assert_eq!(x.as_slice()[1], 3 * i + 1);
            assert_eq!(x.as_slice()[2], 3 * i);
        }
    }

    #[test]
    #[should_panic]
    fn iter_stride_mismatch() {
        let data = (0..31).collect::<Vec<_>>();

        DstIterator::<FooRef<usize>>::new(&data, 3);
    }

    #[test]
    #[should_panic]
    fn iter_mut_stride_mismatch() {
        let mut data = (0..31).collect::<Vec<_>>();

        DstIteratorMut::<FooRef<usize>>::new(&mut data, 3);
    }

    #[test]
    fn forward_iterate_mut() {
        let mut data = vec![0; 3 * 10];

        for (i, x) in DstIteratorMut::<FooRef<usize>>::new(&mut data, 3).enumerate() {
            x.as_mut_slice()[0] = 3 * i;
            x.as_mut_slice()[1] = 3 * i + 1;
            x.as_mut_slice()[2] = 3 * i + 2;
        }

        let expected = (0..30).collect::<Vec<_>>();

        assert_eq!(data, expected);
    }

    #[test]
    fn reverse_iterate_mut() {
        let mut data = vec![0; 3 * 10];

        for (i, x) in DstIteratorMut::<FooRef<usize>>::new(&mut data, 3)
            .rev()
            .enumerate()
        {
            x.as_mut_slice()[2] = 3 * i;
            x.as_mut_slice()[1] = 3 * i + 1;
            x.as_mut_slice()[0] = 3 * i + 2;
        }

        let expected = (0..30).rev().collect::<Vec<_>>();

        assert_eq!(data, expected);
    }

    #[test]
    fn parallel_iterate() {
        let data = (0..30).collect::<Vec<_>>();

        let items_iterated = AtomicUsize::new(0);

        ParallelDstIterator::<FooRef<usize>>::new(&data, 3)
            .enumerate()
            .for_each(|(i, x)| {
                assert_eq!(x.as_slice()[0], 3 * i);
                assert_eq!(x.as_slice()[1], 3 * i + 1);
                assert_eq!(x.as_slice()[2], 3 * i + 2);

                items_iterated.fetch_add(1, Ordering::Relaxed);
            });

        assert_eq!(items_iterated.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn parallel_iterate_mut() {
        let mut data = vec![0; 30];

        ParallelDstIteratorMut::<FooRef<usize>>::new(&mut data, 3)
            .enumerate()
            .for_each(|(i, x)| {
                x.as_mut_slice()[0] = 3 * i;
                x.as_mut_slice()[1] = 3 * i + 1;
                x.as_mut_slice()[2] = 3 * i + 2;
            });

        let expected = (0..30).collect::<Vec<_>>();

        assert_eq!(data, expected);
    }
}
