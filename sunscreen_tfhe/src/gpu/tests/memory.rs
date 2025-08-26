use num::Complex;
use rand::{RngCore, rng};
use sunscreen_gpu_runtime::{DeviceId, GpuRuntime, launch_kernel};

use crate::gpu::{
    Scratch, get_runtimes,
    gpu_params::{
        GlweDef, GlweSize, LogPolyDegree, LweDef, LweDim, RadixCount, RadixDecomposition, RadixLog,
    },
    tests::get_shared_memory_bytes,
};

#[test]
fn can_copy_to_and_from_shared_memory() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        let num_blocks = 13;

        // Must match what's in kernel.
        const N: usize = 2345;

        let mut input = GpuRuntime::allocate::<u32>(r, num_blocks * N).unwrap();
        let output = GpuRuntime::allocate::<u32>(r, num_blocks * N).unwrap();

        input
            .as_mut_slice()
            .iter_mut()
            .for_each(|x| *x = rng().next_u32());

        let stream = r.make_stream(0.into()).unwrap();
        let block_size = 128u32;
        let threads = num_blocks as u32 * block_size;

        unsafe {
            launch_kernel!(
                ((threads, block_size))
                ("can_copy_to_and_from_shared_memory")
                (r, stream, get_shared_memory_bytes())
                input,
                output
            )
        }
        .unwrap();

        stream.wait().unwrap();

        assert_eq!(input.as_slice(), output.as_slice());
    }
}

#[test]
fn can_use_scratch() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        let num_blocks = 31;

        // Must match what's in kernel.
        const N: usize = 2344;

        let mut a = GpuRuntime::allocate::<f64>(r, num_blocks * N).unwrap();
        let mut b = GpuRuntime::allocate::<f64>(r, num_blocks * N).unwrap();
        let output = GpuRuntime::allocate::<f64>(r, num_blocks * N).unwrap();

        a.as_mut_slice()
            .iter_mut()
            .for_each(|x| *x = rng().next_u64() as f64);
        b.as_mut_slice()
            .iter_mut()
            .for_each(|x| *x = rng().next_u64() as f64);

        let stream = r.make_stream(0.into()).unwrap();
        let block_size = 128u32;
        let threads = num_blocks as u32 * block_size;
        let grid = (threads, block_size);

        let scratch = Scratch::new(r, grid).unwrap();

        unsafe {
            launch_kernel!(
                (grid)
                ("can_use_scratch")
                (r, stream, get_shared_memory_bytes())
                a,
                b,
                output,
                scratch
            )
        }
        .unwrap();

        stream.wait().unwrap();

        for ((a, b), c) in a
            .as_slice()
            .iter()
            .zip(b.as_slice().iter())
            .zip(output.as_slice().iter())
        {
            // Assuming your CPU and GPU both implement IEEE-754 double precision
            // and default to round-nearest even, this is an exact result.
            assert_eq!(a + b, *c);
        }
    }
}

#[test]
fn can_load_store_ints_to_punbuf() {
    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        // We can pack 32 values into 16 complex numbers
        let n = 8;

        let mut a = GpuRuntime::allocate::<Complex<f64>>(r, n).unwrap();
        let b = a.clone();

        // We're going to store these integers into a complex array. On the
        // GPU, we'll round-trip these integers out of a PunBuf, which internally
        // stores a std::complex<double>*/.
        let vals = vec![
            0x7FF0000000000000u64, // Infinity
            0xFFF0000000000000,    // -Infinity,
            0x7FF0000000001234,    // NaN
            0x7FF9876000001234,    // also NaN
            0xFFF0000000001234,    // also NaN
            0xFFF9876000001234,    // also NaN
            0x8000000000000000,    // -0.0f64 or u64::MIN
            0x0000000000000000,    // 0.0f64 of 0u64
            0x0000000000000001,    // Some shitty denorms
            0x0000000000000002,    // ...
            0x0000000000000003,    // ...
            0x7000000000000004,    // A large positive u64 and f64 normalized value
            0xFFFFFFFFFFFFFFFF,    // -1u64, also NaN
            0x7FFFFFFFFFFFFFFF,    // u64::MAX, also NaN
            0x8000000000000001,    // Some negative shitty denorm
            0xF000000000000004,    // A large negative u64 and f64 normalized value
        ];

        for (c, a) in bytemuck::cast_slice_mut::<_, u64>(a.as_mut_slice())
            .iter_mut()
            .zip(vals.iter())
        {
            *c = *a;
        }

        let stream = r.make_stream(0.into()).unwrap();
        let block_size = vals.len() as u32;
        let threads = block_size;

        unsafe {
            launch_kernel!(
                ((threads, block_size))
                ("can_load_store_ints_to_punbuf")
                (r, stream, get_shared_memory_bytes())
                a,
                b,
                vals.len() as u32
            )
        }
        .unwrap();

        stream.wait().unwrap();

        // Assert the kernel copied our values as u64s with *no* interpretation
        // as f64s.
        for (e, a) in vals
            .iter()
            .zip(bytemuck::cast_slice::<_, u64>(b.as_slice()))
        {
            assert_eq!(e, a);
        }
    }
}

#[test]
fn can_marshal_params() {
    let lwe = LweDef(LweDim(42));

    let glwe = GlweDef {
        log_poly_degree: LogPolyDegree(43),
        size: GlweSize(44),
    };

    let radix = RadixDecomposition {
        count: RadixCount(45),
        radix_log: RadixLog(46),
    };

    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        let result = GpuRuntime::allocate::<u32>(r, 5).unwrap();

        let stream = r.make_stream(DeviceId(0)).unwrap();

        unsafe {
            launch_kernel!(
                ((1, 1))
                ("can_marshal_params")
                (r, stream, 0)
                lwe,
                glwe,
                radix,
                result
            )
        }
        .unwrap();

        stream.wait().unwrap();

        assert_eq!(result.as_slice()[0], 42);
        assert_eq!(result.as_slice()[1], 43);
        assert_eq!(result.as_slice()[2], 44);
        assert_eq!(result.as_slice()[3], 45);
        assert_eq!(result.as_slice()[4], 46);
    }
}
