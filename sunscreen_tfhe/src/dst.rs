use bytemuck::Pod;

use crate::error::*;

macro_rules! dst {
    ($(#[$meta:meta])* $t:ty, $ref_t:ty, $wrapper:ty, ($($derive:ident),* $(,)? ), ($($t_bounds:ty),* $(,)? )) => {
        paste::paste! {

            $(#[$meta])*
            #[derive($($derive,)* PartialEq)]
            pub struct $t<T> where T: Clone + bytemuck::Pod $(+ $t_bounds)* {
                data: $crate::dst::Allocation<$wrapper<T>>
            }

            /// A reference to the data structure.
            #[repr(transparent)]
            #[derive(PartialEq)]
            pub struct $ref_t<T> where T: Clone $(+ $t_bounds)* {
                data: [$wrapper<T>],
            }

            impl<T> $ref_t<T> where T: Clone $(+ $t_bounds)* {
                #[allow(unused)]
                /// Clones the contents of rhs into self
                pub fn clone_from_ref(&mut self, rhs: &$ref_t<T>) {
                    for (l, r) in self.data.iter_mut().zip(rhs.data.iter()) {
                        *l = r.clone();
                    }
                }
            }

            impl<T> crate::dst::AsSlice<$wrapper<T>> for $ref_t<T> where T: Clone $(+ $t_bounds)* {
                #[allow(unused)]
                /// Returns a slice view of the data representing a $t.
                fn as_slice(&self) -> &[$wrapper<T>] {
                    &self.data
                }
            }

            impl<T> crate::dst::AsMutSlice<$wrapper<T>> for $ref_t<T> where T: Clone $(+ $t_bounds)* {
                #[inline(always)]
                /// Returns a mutable slice view of the data representing a $t.
                fn as_mut_slice(&mut self) -> &mut [$wrapper<T>] {
                    &mut self.data
                }
            }

            impl<T> crate::dst::FromSlice<$wrapper<T>> for $ref_t<T> where T: Clone $(+ $t_bounds)* {
                fn from_slice(s: &[$wrapper<T>]) -> &$ref_t<T> {
                    // Casting the slice to the ref type is sound because it is #[repr(transparent)]
                    unsafe { &*(s as *const [$wrapper<T>] as *const $ref_t<T>) }
                }
            }

            impl<T> crate::dst::FromMutSlice<$wrapper<T>> for $ref_t<T> where T: Clone $(+ $t_bounds)* {
                fn from_mut_slice(s: &mut [$wrapper<T>]) -> &mut $ref_t<T> {
                    // Casting the mut slice to the mut ref type is sound because it is #[repr(transparent)]
                    unsafe { &mut *(s as *mut [$wrapper<T>] as *mut $ref_t<T>) }
                }
            }

            impl<T> crate::dst::Len for $ref_t<T> where T: Clone $(+ $t_bounds)* {
                #[inline(always)]
                fn len(&self) -> usize {
                    use crate::dst::AsSlice;

                    self.as_slice().len()
                }
            }

            impl<T> $ref_t<T> where T: Clone $(+ $t_bounds)*, $wrapper<T>: num::Zero {
                #[allow(unused)]
                /// Clears the contents of self to contain zero
                pub fn clear(&mut self) {
                    use crate::dst::AsMutSlice;

                    for x in self.as_mut_slice() {
                        *x = <$wrapper<T> as num::Zero>::zero();
                    }
                }
            }

            impl<T> std::borrow::Borrow< $ref_t <T>> for $t<T> where T: Clone + bytemuck::Pod $(+ $t_bounds)* {
                fn borrow(&self) -> &$ref_t<T> {
                    let ptr = self.data.as_slice() as *const [$wrapper<T>] as *const $ref_t<T>;

                    unsafe { &*ptr }

                }
            }

            impl<T> std::convert::AsRef< $ref_t <T>> for $t<T> where T: Clone + bytemuck::Pod $(+ $t_bounds)*
            {
                fn as_ref(&self) -> &$ref_t<T> {
                    <Self as std::borrow::Borrow<$ref_t <T>>>::borrow(self)
                }
            }

            impl<T> std::borrow::BorrowMut< $ref_t<T>> for $t<T> where T: Clone + bytemuck::Pod $(+ $t_bounds)* {
                fn borrow_mut(&mut self) -> &mut $ref_t<T> {
                    let ptr = self.data.as_mut_slice() as *mut [$wrapper<T>] as *mut $ref_t<T>;

                    unsafe { &mut *ptr }

                }
            }

            impl<T> std::borrow::ToOwned for $ref_t<T> where T: Clone + Default + bytemuck::Pod $(+ $t_bounds)* {
                type Owned = $t<T>;

                fn to_owned(&self) -> Self::Owned {
                    let mut data = $crate::dst::dst_allocate(self.data.len());
                    data.as_mut_slice().clone_from_slice(&self.data);

                    $t { data }
                }
            }

            impl<T> std::ops::Deref for $t<T> where T: Clone + bytemuck::Pod $(+ $t_bounds)* {
                type Target = $ref_t<T>;

                fn deref(&self) -> &Self::Target {
                    <Self as std::borrow::Borrow::<$ref_t<T>>>::borrow(&self)
                }
            }

            impl<T> std::ops::DerefMut for $t<T> where T: Clone + bytemuck::Pod $(+ $t_bounds)* {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    <Self as std::borrow::BorrowMut::<$ref_t<T>>>::borrow_mut(self)
                }
            }

            #[cfg(feature = "gpu")]
            impl<T> sunscreen_gpu_runtime::AsKernelArg for $ref_t<T> where T: Clone + bytemuck::Pod $(+ $t_bounds)* {
                fn as_kernel_arg(&self) -> *const std::ffi::c_void {
                    (&self.data).as_ptr() as *const std::ffi::c_void
                }
            }

            impl<T> $crate::dst::InnermostType for $t<T>
            where
                T: Clone + bytemuck::Pod $(+ $t_bounds)*
            {
                type Ty = $wrapper<T>;
            }


            impl<T> $crate::dst::InnermostType for $ref_t<T>
            where
                T: Clone + bytemuck::Pod $(+ $t_bounds)*
            {
                type Ty = $wrapper<T>;
            }
        }
    };
}
pub trait InnermostType {
    type Ty: Pod;
}

pub type NoWrapper<T> = T;

pub trait AsSlice<T> {
    fn as_slice(&self) -> &[T];
}

pub trait AsMutSlice<T> {
    fn as_mut_slice(&mut self) -> &mut [T];
}

/// The length of an entity in fundamental elements (i.e. the type of polynomial coefficients in the underlying scheme).
pub trait Len {
    /// Gets the length of this entity in fundamental elements.
    fn len(&self) -> usize;
}

/// Describes how large an entity will be for the given parameters.
pub trait OverlaySize: Len {
    /// The inputs that determine this entity's size
    type Inputs: Copy + Clone;

    /// Get the size of the entity.
    fn size(t: Self::Inputs) -> usize;

    #[inline(always)]
    /// Returns if this entity is the correct length for the given input parameters
    fn check_is_valid(&self, t: Self::Inputs) -> Result<()> {
        if self.len() == Self::size(t) {
            Ok(())
        } else {
            Err(Error::InvalidSize)
        }
    }

    #[inline(always)]
    /// Panics if this entity is not of the correct length.
    fn assert_is_valid(&self, t: Self::Inputs) {
        self.check_is_valid(t)
            .expect("Entity was not the correct length.");
    }
}

impl<S: Pod> Len for [S] {
    fn len(&self) -> usize {
        self.len()
    }
}

impl<S: Pod> OverlaySize for [S] {
    type Inputs = usize;

    fn size(t: Self::Inputs) -> usize {
        t
    }
}
pub trait FromSlice<T> {
    fn from_slice(data: &[T]) -> &Self;
}

pub trait FromMutSlice<T> {
    fn from_mut_slice(data: &mut [T]) -> &mut Self;
}

#[cfg(feature = "gpu")]
mod alloc {
    use bytemuck::Pod;

    pub(crate) type Allocation<T> = sunscreen_gpu_runtime::Allocation<T>;

    pub fn dst_allocate<T>(len: usize) -> Allocation<T>
    where
        T: Pod + Default,
    {
        use sunscreen_gpu_runtime::GpuRuntime;

        use crate::gpu::get_runtimes;

        let mut allocation = GpuRuntime::allocate(&get_runtimes()[0], len).unwrap();

        // Zero the allocation because most of our code assumes owned allocations
        // are such.
        allocation.as_mut_slice().fill(T::default());

        allocation
    }

    pub fn dst_from_iter<T, I: ExactSizeIterator<Item = T>>(iter: I) -> Allocation<T>
    where
        T: Pod + Default,
    {
        let mut allocation = dst_allocate(iter.len());

        for (o, i) in allocation.as_mut_slice().iter_mut().zip(iter) {
            *o = i;
        }

        allocation
    }

    pub fn dst_from_slice<T>(data: &[T]) -> Allocation<T>
    where
        T: Pod + Default,
    {
        let mut allocation = dst_allocate(data.len());

        allocation.as_mut_slice().copy_from_slice(data);

        allocation
    }
}

#[cfg(not(feature = "gpu"))]
mod alloc {
    use aligned_vec::{AVec, ConstAlign, avec};
    use bytemuck::Pod;

    use crate::scratch::SIMD_ALIGN;

    pub(crate) type Allocation<T> = AVec<T, ConstAlign<{ SIMD_ALIGN }>>;

    pub fn dst_allocate<T>(len: usize) -> Allocation<T>
    where
        T: Pod + Default,
    {
        avec![[SIMD_ALIGN]| T::default(); len]
    }

    pub fn dst_from_iter<T, I: ExactSizeIterator<Item = T>>(iter: I) -> Allocation<T>
    where
        T: Pod + Default,
    {
        aligned_vec::AVec::<_, aligned_vec::ConstAlign<{ SIMD_ALIGN }>>::from_iter(
            crate::scratch::SIMD_ALIGN,
            iter,
        )
    }

    pub fn dst_from_slice<T>(data: &[T]) -> Allocation<T>
    where
        T: Pod + Default,
    {
        AVec::from_slice(SIMD_ALIGN, data)
    }
}

pub(crate) use alloc::*;
