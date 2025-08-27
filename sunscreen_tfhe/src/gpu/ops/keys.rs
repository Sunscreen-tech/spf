use num::Complex;
use sunscreen_gpu_runtime::{launch_kernel, DeviceId, GpuRuntime, Stream};

use crate::{
    Error, GlweDef, LweDef, RadixDecomposition,
    entities::{BootstrapKeyFftRef, BootstrapKeyRef},
    gpu::{get_runtimes, gpu_params::{LweDef as GpuLweDef, GlweDef as GpuGlweDef, RadixDecomposition as GpuRadixDecomposition}},
};

/// Take the FFT of the given bootstrapping key.
pub fn gpu_fft_bootstrap_key(
    bsk_fft: &mut BootstrapKeyFftRef<Complex<f64>>,
    bsk: &BootstrapKeyRef<u64>,
    lwe: &LweDef,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
    runtime: &GpuRuntime,
    stream: &Stream
) -> Result<(), Error> {

    let tpb = glwe.dim.polynomial_degree.threads_per_block();
    let threads = lwe.dim.0 as u32 * tpb;

    let lwe = GpuLweDef::from(lwe);
    let glwe = GpuGlweDef::from(glwe);
    let radix = GpuRadixDecomposition::from(radix);

    // TODO: Be smarter about shared memory.
    unsafe {
        launch_kernel!(
            ((threads, tpb))
            ("kernel_fft_bootstrap_key")
            (runtime, stream, 0x1 << 16)
            bsk_fft,
            bsk,
            lwe,
            glwe,
            radix
        )
    }?;

    Ok(())
}
