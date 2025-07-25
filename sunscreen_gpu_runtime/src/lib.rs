#[cfg(feature = "cuda")]
pub mod cuda_runtime;

mod error;
use std::{ffi::c_void, marker::PhantomData};

use bytemuck::{NoUninit, Pod};
pub use error::*;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DeviceId(pub usize);

impl From<usize> for DeviceId {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

impl<T> AsBytes for &[T]
where
    T: NoUninit,
{
    fn as_bytes(&self) -> &[u8] {
        bytemuck::cast_slice(self)
    }
}

pub struct GpuRuntime(pub(crate) Box<dyn GpuRuntimeBackend>);

impl GpuRuntime {
    pub fn new<T: GpuRuntimeBackend + 'static>(backend: T) -> Self {
        Self(Box::new(backend))
    }

    /// Print information about the given device.
    pub fn print_device_info(&self, device_id: DeviceId) -> Result<()> {
        self.0.print_device_info(device_id)
    }

    /// Get the number of GPU devices compatible with this runtime.
    pub fn num_devices(&self) -> Result<usize> {
        self.0.num_devices()
    }

    /// Allocate an array of `len` elements of type `T`.
    ///
    /// # Remarks
    /// This function will allocate space using virtual pages accessible from both
    /// device and host.
    pub fn allocate<T: bytemuck::Pod>(&self, len: usize) -> Result<Allocation<T>> {
        let byte_len = len * std::mem::size_of::<T>();

        Ok(Allocation {
            inner: self.0.allocate(byte_len)?,
            _phantom: PhantomData,
        })
    }

    /// Makes an independent queue for GPU kernels. Kernels enqueued on separate streams
    /// run in parallel.
    pub fn make_stream(&self) -> Result<Stream> {
        Ok(Stream(self.0.make_stream()?))
    }

    pub unsafe fn launch_kernel<'a, G: Grid>(
        &'a self,
        stream: &Stream<'a>,
        name: &str,
        grid: G,
        args: &[*const c_void],
        device_id: DeviceId,
    ) -> Result<()> {
        unsafe {
            self.0
                .launch_kernel(&stream.0, name, &grid, args, device_id)?;
        }

        Ok(())
    }
}

#[macro_export]
macro_rules! launch_kernel {
    (($grid:expr) ($name:literal) ($rt:ident,$stream:ident,$device_id:expr) $($args:expr),*) => {{
        let kernel_args = vec![
            $(
                $args.as_kernel_arg(),
            )*
        ];

        let result = $rt.launch_kernel(&$stream, $name, $grid, kernel_args.as_slice(), $device_id.into());

        result
    }};
}

pub struct Stream<'a>(Box<dyn StreamBackend + 'a>);

impl<'a> Stream<'a> {
    /// Wait for all work on this stream to complete.
    pub fn wait(&self) -> Result<()> {
        self.0.wait()
    }
}

pub trait GpuRuntimeBackend: Sync + Send {
    /// Print information about the given device.
    fn print_device_info(&self, device_id: DeviceId) -> Result<()>;

    /// Get the number of GPU devices.
    fn num_devices(&self) -> Result<usize>;

    /// Allocate an uninitialized block of `len` bytes. This is sound because the
    /// underlying data is a slice of u8, which obeys the requirements of
    /// [bytemuck::Pod].
    ///
    /// # Remarks
    /// This function is useful when you wish to allocate space for an object without
    /// paging it in on the host. This is useful if you have buffers that won't ever
    /// be ready by the host (e.g. intermediate computations).
    ///
    /// This method should allocate unified memory (i.e. IOMMU mapped pages) so data
    /// seamlessly transfers between host and device(s). E.g. as with `cudaMallocManaged`.
    fn allocate(&self, len: usize) -> Result<Box<dyn AllocationBackend>>;

    /// Makes an independent queue for GPU kernels. Kernels enqueued on separate streams
    /// run in parallel.
    fn make_stream<'a>(&'a self) -> Result<Box<dyn StreamBackend + 'a>>;

    unsafe fn launch_kernel<'a>(
        &'a self,
        stream: &Box<dyn StreamBackend + 'a>,
        name: &str,
        grid: &dyn Grid,
        args: &[*const c_void],
        device_id: DeviceId,
    ) -> Result<()>;

    /// Whether or not this runtime allows non-uniform thread blocks.
    fn allows_nonuniform_thread_blocks(&self) -> bool;
}

pub trait StreamBackend {
    unsafe fn launch_kernel(
        &self,
        kernel_name: &str,
        grid: &dyn Grid,
        args: &[*const c_void],
    ) -> Result<()>;

    fn wait(&self) -> Result<()>;
}

/// An array of type `T` allocated in virtual memory accessible from GPUs and the host.
pub struct Allocation<T>
where
    T: Pod,
{
    pub(crate) inner: Box<dyn AllocationBackend>,
    pub(crate) _phantom: PhantomData<T>,
}

impl<T> Allocation<T>
where
    T: Pod,
{
    pub unsafe fn as_slice(&self) -> &[T] {
        bytemuck::cast_slice(unsafe { self.inner.as_slice() })
    }

    pub unsafe fn as_mut_slice(&mut self) -> &mut [T] {
        bytemuck::cast_slice_mut(unsafe { self.inner.as_mut_slice() })
    }
}

pub trait AsKernelArg {
    fn as_kernel_arg(&self) -> *const c_void;
}

impl<T> AsKernelArg for Allocation<T>
where
    T: Pod,
{
    fn as_kernel_arg(&self) -> *const c_void {
        self.inner.ptr() as *const c_void
    }
}

macro_rules! impl_as_kernel_arg {
    ($($ty:ty),*) => {
        $(
            impl $crate::AsKernelArg for $ty {
                fn as_kernel_arg(&self) -> *const c_void {
                    *self as *const c_void
                }
            }
        )*
    };
}

impl_as_kernel_arg!(u8, u16, u32, u64, i8, i16, i32, i64);

pub trait AllocationBackend {
    fn ptr(&self) -> *const u8;

    fn ptr_mut(&self) -> *mut u8;

    /// Get the underlying GPU-accessible buffer as a slice.
    /// TODO: Can use use an [`AtomicRefCell`]` and to remove the unsafe?
    ///
    /// # Safety
    /// You must not call this method while a GPU kernel that writes to the underlying buffer
    /// is running. You must additionally obey Rust's standard aliasing rules.
    unsafe fn as_slice(&self) -> &[u8];

    /// Get the underlying GPU-accessible buffer as a mutable slice.
    /// TODO: Can use use an [`AtomicRefCell`]` and to remove the unsafe?
    ///
    /// # Safety
    /// You must not call this method while a GPU kernel that writes to the underlying buffer
    /// is running. You must additionally obey Rust's standard aliasing rules.
    unsafe fn as_mut_slice(&mut self) -> &mut [u8];
}

#[derive(Copy, Clone, Debug)]
/// A struct describing a dimension of a [`Grid`].
///
/// # Remarks
/// Uses OpenCL's grid language where you specify the total number of threads in a given
/// dimension and the number of threads per block.
pub struct Dim {
    /// The total number of desired threads in this dimension.
    total_threads: u32,

    /// The number of threads per thread block in this dimension. This results in
    /// `total_threads / threads_per_block` blocks being spawned.
    ///
    /// If [`GpuRuntime::allows_nonuniform_thread_blocks`] returns false, then
    /// `total_threads % threads_per_block` must be true or launching the kernel results
    /// in an error.
    threads_per_block: u32,
}

const DIM_ONE: Dim = Dim {
    total_threads: 1,
    threads_per_block: 1,
};

pub trait Grid {
    fn x(&self) -> Dim;
    fn y(&self) -> Dim;
    fn z(&self) -> Dim;
}

impl Grid for (u32, u32) {
    fn x(&self) -> Dim {
        Dim {
            total_threads: self.0,
            threads_per_block: self.1,
        }
    }

    fn y(&self) -> Dim {
        DIM_ONE
    }

    fn z(&self) -> Dim {
        DIM_ONE
    }
}

impl Grid for ((u32, u32), (u32, u32)) {
    fn x(&self) -> Dim {
        Dim {
            total_threads: self.0.0,
            threads_per_block: self.0.1,
        }
    }

    fn y(&self) -> Dim {
        Dim {
            total_threads: self.1.0,
            threads_per_block: self.1.1,
        }
    }

    fn z(&self) -> Dim {
        DIM_ONE
    }
}

impl Grid for ((u32, u32), (u32, u32), (u32, u32)) {
    fn x(&self) -> Dim {
        Dim {
            total_threads: self.0.0,
            threads_per_block: self.0.1,
        }
    }

    fn y(&self) -> Dim {
        Dim {
            total_threads: self.1.0,
            threads_per_block: self.1.1,
        }
    }

    fn z(&self) -> Dim {
        Dim {
            total_threads: self.2.0,
            threads_per_block: self.2.1,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, OnceLock};

    #[cfg(feature = "cuda")]
    use crate::cuda_runtime::CudaRuntime;

    use super::*;

    static RUNTIMES: OnceLock<Arc<Vec<GpuRuntime>>> = OnceLock::new();

    fn get_runtimes() -> Arc<Vec<GpuRuntime>> {
        RUNTIMES
            .get_or_init(|| {
                let mut runtimes = vec![];

                #[cfg(feature = "cuda")]
                {
                    let cuda: Box<dyn GpuRuntimeBackend> =
                        Box::new(CudaRuntime::new(cuda_runtime::KERNELS).unwrap());
                    let cuda = GpuRuntime(cuda);
                    runtimes.push(cuda);
                }

                Arc::new(runtimes)
            })
            .clone()
    }

    #[test]
    fn can_print_device_info() {
        for runtime in get_runtimes().iter() {
            for i in 0..runtime.num_devices().unwrap() {
                runtime.print_device_info(i.into()).unwrap();
            }
        }
    }

    #[test]
    fn can_allocate_data() {
        for runtime in get_runtimes().iter() {
            let mut data = runtime.allocate::<u64>(1234).unwrap();
            let data = unsafe { data.as_mut_slice() };

            for (i, d) in data.iter_mut().enumerate() {
                *d = i as u64;
            }

            for (i, d) in data.iter().enumerate() {
                assert_eq!(*d, i as u64);
            }
        }
    }

    #[test]
    fn can_run_kernel() {
        for runtime in get_runtimes().iter() {
            let x = (0..1234).map(|x| x as f32).collect::<Vec<_>>();
            let y = (1234..2468).map(|x| x as f32).collect::<Vec<_>>();

            let mut x_gpu = runtime.allocate::<f32>(x.len()).unwrap();
            let mut y_gpu = runtime.allocate::<f32>(y.len()).unwrap();
            let z_gpu = runtime.allocate::<f32>(y.len()).unwrap();

            let x_gpu_slice = unsafe { x_gpu.as_mut_slice() };
            x_gpu_slice.copy_from_slice(&x);
            let y_gpu_slice = unsafe { y_gpu.as_mut_slice() };
            y_gpu_slice.copy_from_slice(&y);

            let block_size = 64u32;
            let threads = (x.len() as u32).next_multiple_of(block_size);

            let stream = runtime.make_stream().unwrap();

            unsafe {
                launch_kernel!
                    (((threads, block_size))
                    ("vector_add")
                    (runtime, stream, 0)
                    x_gpu,
                    y_gpu,
                    z_gpu,
                    x.len() as u32
                )
                .unwrap();
            }

            stream.wait().unwrap();

            let z_gpu = unsafe { z_gpu.as_slice() };

            dbg!(z_gpu);

            for (z, (x, y)) in z_gpu.iter().zip(x.iter().zip(y.iter())) {
                assert_eq!(*z, *x + *y);
            }
        }
    }
}
