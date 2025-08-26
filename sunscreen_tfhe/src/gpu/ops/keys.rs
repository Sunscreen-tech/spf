use num::Complex;
use sunscreen_gpu_runtime::{DeviceId, launch_kernel};

use crate::{
    Error, GlweDef, LweDef, RadixDecomposition,
    entities::{BootstrapKeyFftRef, BootstrapKeyRef},
    gpu::get_runtimes,
};

/// Take the FFT of the given bootstrapping key.
pub fn fft_bootstrap_key(
    bsk_fft: &mut BootstrapKeyFftRef<Complex<f64>>,
    bsk: &BootstrapKeyRef<u64>,
    lwe: LweDef,
    glwe: GlweDef,
    radix: RadixDecomposition,
) -> Result<(), Error> {
    // TODO: actually use parameters rather than just assert the user is doing what they
    // think they are.
    assert_eq!(lwe.dim.0, 637);
    assert_eq!(glwe.dim.polynomial_degree.0, 2048);
    assert_eq!(glwe.dim.size.0, 1);
    assert_eq!(radix.count.0, 2);
    assert_eq!(radix.radix_log.0, 16);

    let runtimes = get_runtimes();

    let r = &runtimes[0];
    let stream = r.make_stream(DeviceId(0)).unwrap();

    let tpb = glwe.dim.polynomial_degree.threads_per_block();
    let threads = lwe.dim.0 as u32 * tpb;

    unsafe {
        launch_kernel!(
            ((threads, tpb))
            ("fft_bootstrap_key")
            (r, stream, 0)
            bsk_fft,
            bsk
        )
    }?;

    stream.wait()?;

    Ok(())
}
