#[cfg(feature = "cuda")]
pub mod cuda_runtime;

mod error;
use std::{
    borrow::{Borrow, BorrowMut},
    ffi::c_void,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use bytemuck::{NoUninit, Pod};
pub use error::*;
use serde::{Deserialize, Serialize, de::Visitor};

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

    /// Returns the name of this runtime.
    pub fn name(&self) -> &str {
        self.0.runtime_name()
    }

    /// Print information about the given device.
    pub fn print_device_info(&self, device_id: DeviceId) -> Result<()> {
        self.0.print_device_info(device_id)
    }

    pub fn get_device_name(&self, device_id: DeviceId) -> Result<String> {
        self.0.get_device_name(device_id)
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
    pub fn allocate<T: bytemuck::Pod>(this: &Arc<Self>, len: usize) -> Result<Allocation<T>> {
        let byte_len = len * std::mem::size_of::<T>();

        Ok(Allocation {
            runtime: this.clone(),
            inner: this.0.allocate(byte_len)?,
            _phantom: PhantomData,
        })
    }

    /// Makes an independent queue for GPU kernels. Kernels enqueued on separate streams
    /// run in parallel.
    pub fn make_stream(&self, device_id: DeviceId) -> Result<Stream<'_>> {
        Ok(Stream(self.0.make_stream(device_id)?))
    }

    /// Launch a GPU kernel on the given stream and device.
    ///
    /// # Remarks
    /// Don't use this directly. use the [launch_kernel] macro.
    ///
    /// # Safety
    /// The given arguments must be the result of an `as_kernel_arg` call.
    /// The number and types of arguments must match what's in the kernel declaration.
    ///
    /// You must ensure the kernel you launch doesn't violate Rust's aliasing requirements.
    /// In particular, your host program should have no slices outstanding on any allocation
    /// this kernel writes to during kernel execution.
    pub unsafe fn launch_kernel<'a, G: Grid>(
        &'a self,
        stream: &Stream<'a>,
        name: &str,
        grid: G,
        args: &[*const c_void],
    ) -> Result<()> {
        unsafe {
            self.0.launch_kernel(stream.0.as_ref(), name, &grid, args)?;
        }

        Ok(())
    }
}

/// Launches the kernel with the given name on the given device and stream.
/// This is the sanctioned mechanism for launching kernels that unpacks arguments
/// as needed.
///
/// # Safety
/// You must ensure the kernel you launch doesn't violate Rust's aliasing requirements.
/// In particular, your host program should have no slices outstanding on any allocation
/// this kernel writes to during kernel execution.
#[macro_export]
macro_rules! launch_kernel {
    (($grid:expr) ($name:expr) ($rt:ident,$stream:ident) $($args:expr),*) => {{
        let kernel_args = vec![
            $(
                $crate::AsKernelArg::as_kernel_arg(&$args),
            )*
        ];

        let result = $rt.launch_kernel(&$stream, $name, $grid, kernel_args.as_slice());

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
    fn runtime_name(&self) -> &str;

    /// Print information about the given device.
    fn print_device_info(&self, device_id: DeviceId) -> Result<()>;

    /// Get the name of the given device.
    fn get_device_name(&self, device_id: DeviceId) -> Result<String>;

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
    fn make_stream<'a>(&'a self, device_id: DeviceId) -> Result<Box<dyn StreamBackend + 'a>>;

    /// Launch a GPU kernel on the given stream and device.
    ///
    /// # Safety
    /// The given arguments must be the result of an `as_kernel_arg` call.
    /// The number and types of arguments must match what's in the kernel declaration
    ///
    /// You must ensure the kernel you launch doesn't violate Rust's aliasing requirements.
    /// In particular, your host program should have no slices outstanding on any allocation
    /// this kernel writes to during kernel execution.
    unsafe fn launch_kernel<'a>(
        &'a self,
        stream: &'a dyn StreamBackend,
        name: &str,
        grid: &dyn Grid,
        args: &[*const c_void],
    ) -> Result<()>;

    /// Whether or not this runtime allows non-uniform thread blocks.
    fn allows_nonuniform_thread_blocks(&self) -> bool;
}

pub trait StreamBackend {
    /// Launch a GPU kernel on this stream and the given device.
    ///
    /// # Safety
    /// The given arguments must be the result of an `as_kernel_arg` call.
    /// The number and types of arguments must match what's in the kernel declaration
    ///
    /// You must ensure the kernel you launch doesn't violate Rust's aliasing requirements.
    /// In particular, your host program should have no slices outstanding on any allocation
    /// this kernel writes to during kernel execution.
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
    runtime: Arc<GpuRuntime>,
    pub(crate) inner: Box<dyn AllocationBackend>,
    pub(crate) _phantom: PhantomData<T>,
}

impl<T> std::fmt::Debug for Allocation<T>
where
    T: Pod + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <[T] as std::fmt::Debug>::fmt(self.as_slice(), f)
    }
}

impl<T> Serialize for Allocation<T>
where
    T: Pod + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        <[T] as Serialize>::serialize(self.as_slice(), serializer)
    }
}

struct AllocationVisitor<'a, T>
where
    T: Pod,
{
    gpu_runtime: &'a Arc<GpuRuntime>,
    _phantom: PhantomData<T>,
}

impl<'de, 'a, T> Visitor<'de> for AllocationVisitor<'a, T>
where
    T: Pod + Deserialize<'de>,
{
    type Value = Allocation<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequency of T elements")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
        A::Error: serde::de::Error,
    {
        use serde::de::Error;

        let len = seq.size_hint();

        let try_allocate = |len: usize| {
            GpuRuntime::allocate(self.gpu_runtime, len).map_err(|_| {
                A::Error::custom(&format!(
                    "Failed to allocate {} bytes on runtime {}",
                    std::mem::size_of::<T>() * len,
                    self.gpu_runtime.name()
                ))
            })
        };

        match len {
            // If we have a length, we can directly deserialize into the Allocation...
            Some(len) => {
                let mut allocation = try_allocate(len)?;

                for i in 0..len {
                    let next_element = seq
                        .next_element::<T>()?
                        .ok_or_else(|| A::Error::invalid_length(i, &self))?;

                    allocation.as_mut_slice()[i] = next_element;
                }

                Ok(allocation)
            }
            // ... If not, deserialize into Vec as Rust's internal allocator is almost certainly
            // faster than a GPU runtime, which often gets the driver involved. Then, copy
            // all the data into the allocation.
            None => {
                let mut tmp = vec![];

                while let Some(x) = seq.next_element::<T>()? {
                    tmp.push(x);
                }

                let mut allocation = try_allocate(tmp.len())?;

                allocation.as_mut_slice().copy_from_slice(tmp.as_slice());

                Ok(allocation)
            }
        }
    }
}

impl<'de, T> Deserialize<'de> for Allocation<T>
where
    T: Pod + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let visitor = AllocationVisitor {
            gpu_runtime: &get_runtimes()[0],
            _phantom: PhantomData,
        };

        deserializer.deserialize_seq(visitor)
    }
}

impl<T> Clone for Allocation<T>
where
    T: Pod,
{
    fn clone(&self) -> Self {
        let s = self.as_slice();

        // Memory allocation failures tend to kill apps, so unwrapping here is probably
        // fine.
        let mut other = GpuRuntime::allocate::<T>(&self.runtime, s.len()).unwrap();

        other.copy_from_slice(s);

        other
    }
}

impl<T> PartialEq for Allocation<T>
where
    T: PartialEq + Pod,
{
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T> Borrow<[T]> for Allocation<T>
where
    T: Pod,
{
    fn borrow(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T> BorrowMut<[T]> for Allocation<T>
where
    T: Pod,
{
    fn borrow_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<T> AsRef<[T]> for Allocation<T>
where
    T: Pod,
{
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T> AsMut<[T]> for Allocation<T>
where
    T: Pod,
{
    fn as_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<T> Deref for Allocation<T>
where
    T: Pod,
{
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T> DerefMut for Allocation<T>
where
    T: Pod,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<T> Eq for Allocation<T> where T: Eq + Pod {}

impl<T> Allocation<T>
where
    T: Pod,
{
    /// Get a slice to the underlying allocation.
    pub fn as_slice(&self) -> &[T] {
        bytemuck::cast_slice(self.inner.as_slice())
    }

    /// Get a mutable slice to the underlying allocation.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        bytemuck::cast_slice_mut(self.inner.as_mut_slice())
    }

    pub fn copy_from_slice(&mut self, other: &[T]) {
        self.as_mut_slice().copy_from_slice(other);
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &T> {
        self.as_slice().iter()
    }

    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = &mut T> {
        self.as_mut_slice().iter_mut()
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

pub trait AllocationBackend: Sync + Send {
    fn ptr(&self) -> *const u8;

    fn ptr_mut(&self) -> *mut u8;

    /// Get the underlying GPU-accessible buffer as a slice.
    fn as_slice(&self) -> &[u8];

    /// Get the underlying GPU-accessible buffer as a mutable slice.
    fn as_mut_slice(&mut self) -> &mut [u8];
}

#[derive(Copy, Clone, Debug)]
/// A struct describing a dimension of a [`Grid`].
///
/// # Remarks
/// Uses OpenCL's grid language where you specify the total number of threads in a given
/// dimension and the number of threads per block.
pub struct Dim {
    #[allow(unused)]
    /// The total number of desired threads in this dimension.
    pub total_threads: u32,

    #[allow(unused)]
    /// The number of threads per thread block in this dimension. This results in
    /// `total_threads / threads_per_block` blocks being spawned.
    ///
    /// If [`GpuRuntime::allows_nonuniform_thread_blocks`] returns false, then
    /// `total_threads % threads_per_block` must be true or launching the kernel results
    /// in an error.
    pub threads_per_block: u32,
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

static RUNTIMES: OnceLock<Arc<Vec<Arc<GpuRuntime>>>> = OnceLock::new();

pub fn init_runtimes(
    // Don't know why the rust compiler complains about this...
    #[allow(unused)] cubin: &[u8],
) {
    static INITIALIZED: AtomicBool = AtomicBool::new(false);

    INITIALIZED
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .expect("GPU runtime already initialized");

    let _ = RUNTIMES.get_or_init(|| {
        let runtimes = vec![
            #[cfg(feature = "cuda")]
            Arc::new(GpuRuntime(Box::new(
                cuda_runtime::CudaRuntime::new(cubin).unwrap(),
            ))),
        ];

        Arc::new(runtimes)
    });
}

pub fn get_runtimes() -> Arc<Vec<Arc<GpuRuntime>>> {
    RUNTIMES
        .get()
        .expect("GPU runtimes not initialized.")
        .clone()
}

#[cfg(all(test, feature = "gpu"))]
mod tests {
    use super::*;

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
            let mut data = GpuRuntime::allocate::<u64>(runtime, 1234).unwrap();
            let data = data.as_mut_slice();

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

            let mut x_gpu = GpuRuntime::allocate::<f32>(runtime, x.len()).unwrap();
            let mut y_gpu = GpuRuntime::allocate::<f32>(runtime, y.len()).unwrap();
            let z_gpu = GpuRuntime::allocate::<f32>(runtime, y.len()).unwrap();

            let x_gpu_slice = x_gpu.as_mut_slice();
            x_gpu_slice.copy_from_slice(&x);
            let y_gpu_slice = y_gpu.as_mut_slice();
            y_gpu_slice.copy_from_slice(&y);

            let block_size = 64u32;
            let threads = (x.len() as u32).next_multiple_of(block_size);

            let stream = runtime.make_stream(0.into()).unwrap();

            unsafe {
                launch_kernel!
                    (((threads, block_size))
                    ("vector_add")
                    (runtime, stream)
                    x_gpu,
                    y_gpu,
                    z_gpu,
                    x.len() as u32
                )
                .unwrap();
            }

            stream.wait().unwrap();

            let z_gpu = z_gpu.as_slice();

            dbg!(z_gpu);

            for (z, (x, y)) in z_gpu.iter().zip(x.iter().zip(y.iter())) {
                assert_eq!(*z, *x + *y);
            }
        }
    }
}
