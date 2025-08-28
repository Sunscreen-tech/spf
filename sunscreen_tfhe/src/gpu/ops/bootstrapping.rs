use std::{os::raw::c_void, ptr, sync::Arc};

use num::Complex;
use sunscreen_gpu_runtime::{DeviceId, GpuRuntime, Stream, launch_kernel};

use crate::{
    GlweDef, LweDef, OverlaySize, RadixDecomposition, Result,
    entities::{
        BootstrapKeyFft, BootstrapKeyFftRef, DstArrayRef, GlweCiphertext, GlweCiphertextRef,
        LweCiphertext, LweCiphertextRef, PolynomialRef, UnivariateLookupTable,
        UnivariateLookupTableRef,
    },
    gpu::gpu_params::{
        GlweDef as GpuGlweDef, LweDef as GpuLweDef, RadixDecomposition as GpuRadixDecomposition,
    },
};

fn pbs_preferred_shared_memory(
    glwe: &GlweDef,
    lwe: &LweDef,
    radix: &RadixDecomposition,
    runtime: &Arc<GpuRuntime>,
    device_id: DeviceId,
) -> u32 {
    let max_sm = runtime
        .get_device_attributes(device_id)
        .max_dynamic_shared_memory_per_block;

    let glwe_size = (GlweCiphertextRef::<u64>::size(glwe.dim) * std::mem::size_of::<u64>()) as u32;
    let poly_size = (PolynomialRef::<u64>::size(glwe.dim.polynomial_degree)
        * std::mem::size_of::<u64>()) as u32;

    // In order of preferences for shared memory:
    // * Nothing :(
    // * A single polynomial for decomposition,      (p)
    // * Above plus a second poly for decomposition  (2p)
    // * Above plus a GLWE ciphertext for cmux "a"   (2p + 1g)
    // * Above plus a GLWE ciphertext for cmux "b"   (2p + 2g)
    // * Above plus a GLWE ciphertext for GGSW terms (2p + 3g)
    //
    // Under standard CBS parameters, this amounts to p=16kB and g=32kB, giving
    // 0kB, 16kB, 32kB, 64kB, 96kB, 128kB respectively.
    let preferences = [
        poly_size,
        2 * poly_size,
        2 * poly_size + glwe_size,
        2 * poly_size + 2 * glwe_size,
        2 * poly_size + 3 * glwe_size,
    ];

    let mut sm_size = 0;

    for p in preferences {
        if p <= max_sm {
            sm_size = p;
        } else {
            break;
        }
    }

    sm_size
}

/// Perform multiple PBS operations on the GPU. For each input `inputs`,
/// apply `lut` and produce the corresponding output in `outputs`.
///
/// See [crate::ops::bootstrapping::generalized_programmable_bootstrap] for more
/// details.
pub fn gpu_generalized_functional_bootstrap(
    outputs: &mut DstArrayRef<GlweCiphertextRef<u64>>,
    inputs: &DstArrayRef<LweCiphertextRef<u64>>,
    lut: &UnivariateLookupTableRef<u64>,
    bsk: &BootstrapKeyFft<Complex<f64>>,
    log_chi: u32,
    log_v: u32,
    lwe: &LweDef,
    glwe: &GlweDef,
    radix: &RadixDecomposition,
    runtime: &Arc<GpuRuntime>,
    stream: &Stream,
) -> Result<()> {
    assert_eq!(outputs.len(glwe.dim), inputs.len(lwe.dim));
    radix.assert_valid::<u64>();
    glwe.assert_valid();
    lwe.assert_valid();

    let sm_size = pbs_preferred_shared_memory(&glwe, &lwe, &radix, runtime, stream.device_id());

    let tpb = glwe.dim.polynomial_degree.threads_per_block();
    let threads = outputs.len(glwe.dim) as u32 * tpb;
    let grid = (threads, tpb);
    let lwe = GpuLweDef::from(lwe);
    let glwe = GpuGlweDef::from(glwe);
    let radix = GpuRadixDecomposition::from(radix);

    unsafe {
        launch_kernel!(
            (grid)
            ("kernel_generalized_functional_bootstrap")
            (runtime, stream, sm_size)
            outputs,
            inputs,
            lut,
            bsk,
            log_chi,
            log_v,
            lwe,
            glwe,
            radix,
            sm_size
        )
    }?;

    Ok(())
}
