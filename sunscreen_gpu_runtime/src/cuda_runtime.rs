use core::slice;
use std::{
    ffi::{CStr, CString, c_char},
    os::raw::c_void,
    ptr::{self},
    str::FromStr,
    sync::OnceLock,
};

use cuda_driver_sys::{
    CUcontext, CUdevice, CUfunction, CUmodule, CUstream, cuCtxSetCurrent,
    cuDeviceComputeCapability, cuDeviceGet, cuDeviceGetName, cuDevicePrimaryCtxRelease,
    cuDevicePrimaryCtxRetain, cuLaunchKernel, cuModuleGetFunction, cuModuleLoadData,
    cuStreamCreate, cuStreamDestroy_v2, cuStreamSynchronize, cudaError_enum,
};
use cuda_runtime_sys::{
    cudaError, cudaFree, cudaGetDeviceCount, cudaMallocManaged, cudaMemAttachGlobal,
};

use crate::{
    AllocationBackend, DeviceId, Dim, Error, GpuRuntimeBackend, Grid, Result, StreamBackend,
};

macro_rules! wrap_cuda_runtime {
    ($expr:expr) => {
        let err = unsafe { $expr };

        if err != cudaError::cudaSuccess {
            return Err(Error::cuda_runtime_err(err));
        }
    };
}

macro_rules! wrap_cuda_driver {
    ($expr:expr) => {
        let err = unsafe { $expr };

        if err != cudaError_enum::CUDA_SUCCESS {
            return Err(Error::cuda_driver_err(err));
        }
    };
}
struct Module {
    module: CUmodule,
}

impl Module {
    fn new(fatbin: &[u8]) -> Result<Self> {
        let mut module = CUmodule::default();
        wrap_cuda_driver! {cuModuleLoadData(&raw mut module, fatbin.as_ptr() as *const c_void)};

        Ok(Self { module })
    }

    fn get_function<'a>(&'a self, name: &str) -> Result<Function> {
        let mut kernel_fn = CUfunction::default();
        let name = CString::from_str(name).map_err(|_| Error::NulError)?;

        wrap_cuda_driver! {cuModuleGetFunction(&raw mut kernel_fn, self.module, name.as_ptr())};

        Ok(Function { inner: kernel_fn })
    }
}

static INIT: OnceLock<Result<()>> = OnceLock::new();

fn ensure_init() -> Result<()> {
    INIT.get_or_init(|| Ok(())).clone()?;

    Ok(())
}

static NUM_DEVICES: OnceLock<Result<usize>> = OnceLock::new();

fn num_devices() -> Result<usize> {
    let count = NUM_DEVICES
        .get_or_init(|| {
            let mut dev_count = 0;

            wrap_cuda_runtime!(cudaGetDeviceCount(&mut dev_count));

            Ok(dev_count as usize)
        })
        .clone()?;

    Ok(count)
}

pub struct Context {
    device: CUdevice,
    ctx: CUcontext,
    module: Module,
}

impl Context {
    fn new(device_id: i32, fatbin: &[u8]) -> Result<Self> {
        let mut device = CUdevice::default();
        wrap_cuda_driver! {cuDeviceGet(&raw mut device, device_id)}

        let mut ctx = CUcontext::default();
        wrap_cuda_driver! {cuDevicePrimaryCtxRetain(&raw mut ctx, device_id)};
        wrap_cuda_driver!(cuCtxSetCurrent(ctx));

        let module = Module::new(fatbin)?;

        Ok(Self {
            ctx,
            device,
            module,
        })
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        let _ = unsafe { cuDevicePrimaryCtxRelease(self.device) };
    }
}

pub struct CudaRuntime {
    ctxs: Vec<Context>,
}

unsafe impl Sync for CudaRuntime {}
unsafe impl Send for CudaRuntime {}

impl CudaRuntime {
    pub fn new(fatbin: &[u8]) -> Result<Self> {
        ensure_init()?;

        let num_devices = num_devices().unwrap();
        let mut ctxs = vec![];

        for i in 0..num_devices {
            ctxs.push(Context::new(i as i32, fatbin)?);
        }

        Ok(Self { ctxs })
    }
}

impl CudaRuntime {
    fn set_device_id(&self, device_id: DeviceId) -> Result<()> {
        let ctx = self.ctxs.get(device_id.0).ok_or(Error::InvalidDevice)?;
        wrap_cuda_driver! { cuCtxSetCurrent(ctx.ctx) };

        Ok(())
    }
}

impl GpuRuntimeBackend for CudaRuntime {
    fn runtime_name(&self) -> &str {
        "CUDA"
    }

    fn print_device_info(&self, device_id: DeviceId) -> Result<()> {
        self.set_device_id(device_id)?;

        println!(
            "Device {}: {}",
            device_id.0,
            self.get_device_name(device_id)?
        );

        let (mut major, mut minor) = (0, 0);
        let mut device = 0;

        wrap_cuda_driver! {cuDeviceGet(&raw mut device, device_id.0 as i32)};
        wrap_cuda_driver! {cuDeviceComputeCapability(&raw mut major, &raw mut minor, device)};

        println!("\tCompute capability: {major}.{minor}",);

        Ok(())
    }

    fn get_device_name(&self, device_id: DeviceId) -> Result<String> {
        self.set_device_id(device_id)?;
        let mut device_name: [u8; 256] = [0; 256];

        // We're loading actual characters, who gives a shit about signed-ness.
        wrap_cuda_driver! {cuDeviceGetName(&raw mut device_name as *mut c_char, (device_name.len() - 1) as i32, device_id.0 as i32)};

        let device_name = CStr::from_bytes_until_nul(&device_name).unwrap();
        Ok(device_name.to_string_lossy().to_string())
    }

    fn num_devices(&self) -> Result<usize> {
        num_devices()
    }

    fn allocate(&self, len: usize) -> Result<Box<dyn AllocationBackend>> {
        let mut dev_ptr = ptr::null_mut();

        wrap_cuda_runtime!(cudaMallocManaged(&mut dev_ptr, len, cudaMemAttachGlobal));

        Ok(Box::new(CudaAllocation {
            ptr: dev_ptr as *mut u8,
            len,
        }))
    }

    fn make_stream<'a>(&'a self, device_id: DeviceId) -> Result<Box<dyn StreamBackend + 'a>> {
        self.set_device_id(device_id)?;
        let mut stream = CUstream::default();
        wrap_cuda_driver! {cuStreamCreate(&mut stream, 0)};

        Ok(Box::new(CudaStream {
            device_id,
            runtime: self,
            handle: stream,
        }))
    }

    fn allows_nonuniform_thread_blocks(&self) -> bool {
        false
    }

    unsafe fn launch_kernel<'a>(
        &'a self,
        stream: &'a dyn StreamBackend,
        name: &str,
        grid: &dyn Grid,
        args: &[*const c_void],
    ) -> Result<()> {
        unsafe { stream.launch_kernel(name, grid, args)? };

        Ok(())
    }
}

pub struct CudaStream<'a> {
    device_id: DeviceId,
    runtime: &'a CudaRuntime,
    handle: CUstream,
}

fn get_threads_per_block(dim: Dim) -> Result<u32> {
    if dim.total_threads == 0
        || dim.threads_per_block == 0
        || dim.total_threads % dim.threads_per_block != 0
    {
        return Err(Error::IllegalGrid);
    }

    Ok(dim.total_threads / dim.threads_per_block)
}

impl<'a> StreamBackend for CudaStream<'a> {
    unsafe fn launch_kernel(
        &self,
        name: &str,
        grid: &dyn Grid,
        args: &[*const c_void],
    ) -> Result<()> {
        let ctx = self
            .runtime
            .ctxs
            .get(self.device_id.0)
            .ok_or(Error::InvalidDevice)?;

        let kernel_fn = ctx.module.get_function(name)?;
        wrap_cuda_driver!(cuCtxSetCurrent(ctx.ctx));

        let dim_x = grid.x();
        let dim_y = grid.y();
        let dim_z = grid.z();

        let tbx = get_threads_per_block(dim_x)?;
        let tby = get_threads_per_block(dim_y)?;
        let tbz = get_threads_per_block(dim_z)?;

        let args = args
            .iter()
            .map(|x| x as *const _ as *const c_void)
            .collect::<Vec<_>>();

        wrap_cuda_driver! {
            cuLaunchKernel(
                kernel_fn.inner,
                tbx,
                tby,
                tbz,
                dim_x.threads_per_block,
                dim_y.threads_per_block,
                dim_z.threads_per_block,
                0,
                self.handle,
                args.as_ptr() as *mut _,
                ptr::null_mut()
            )
        };

        Ok(())
    }

    fn wait(&self) -> Result<()> {
        wrap_cuda_driver!(cuStreamSynchronize(self.handle));

        Ok(())
    }
}

impl<'a> Drop for CudaStream<'a> {
    fn drop(&mut self) {
        let _ = unsafe { cuStreamDestroy_v2(self.handle) };
    }
}

pub struct Function {
    inner: CUfunction,
}

impl<'a> Function {
    fn new(inner: CUfunction, _module: &'a Module) -> Self {
        Self { inner }
    }
}

pub struct CudaAllocation {
    ptr: *mut u8,
    len: usize,
}

unsafe impl Sync for CudaAllocation {}
unsafe impl Send for CudaAllocation {}

impl AllocationBackend for CudaAllocation {
    fn ptr(&self) -> *const u8 {
        self.ptr
    }

    fn ptr_mut(&self) -> *mut u8 {
        self.ptr
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for CudaAllocation {
    fn drop(&mut self) {
        let _ = unsafe { cudaFree(self.ptr as *mut c_void) };
    }
}

#[cfg(not(test))]
pub(crate) const KERNELS: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/sunscreen_gpu_runtime.release.fatbin"
));

#[cfg(test)]
pub(crate) const KERNELS: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/sunscreen_gpu_runtime.test.fatbin"
));
