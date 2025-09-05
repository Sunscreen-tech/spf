use sunscreen_gpu_runtime::{ComputeVersion, DeviceId, GpuRuntime, launch_kernel_cg};

use crate::gpu::get_runtimes;

#[test]
fn can_launch_cluster() {
    const COMPUTE_CAPABILITY_9_0: ComputeVersion = ComputeVersion { major: 9, minor: 0 };

    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        if r.get_device_attributes(DeviceId(0)).compute_version < COMPUTE_CAPABILITY_9_0 {
            return;
        }

        let g_x = 6u32;
        let g_y = 12u32;

        let len = (g_x * g_y) as usize;

        let block_x = GpuRuntime::allocate::<u32>(r, len).unwrap();
        let block_y = GpuRuntime::allocate::<u32>(r, len).unwrap();
        let block_z = GpuRuntime::allocate::<u32>(r, len).unwrap();
        let cluster_x = GpuRuntime::allocate::<u32>(r, len).unwrap();
        let cluster_y = GpuRuntime::allocate::<u32>(r, len).unwrap();
        let cluster_z = GpuRuntime::allocate::<u32>(r, len).unwrap();
        let cluster_rank = GpuRuntime::allocate::<u32>(r, len).unwrap();

        let stream = r.make_stream(DeviceId(0)).unwrap();

        let c_x = 2;
        let c_y = 3;

        unsafe {
            launch_kernel_cg!(
                (((g_x, 1), (g_y, 1)))
                ((c_x, c_y))
                ("can_launch_cluster_group")
                (r, stream, 0)
                block_x,
                block_y,
                block_z,
                cluster_x,
                cluster_y,
                cluster_z,
                cluster_rank
            )
        }
        .unwrap();

        stream.wait().unwrap();

        for i in 0..g_x {
            for j in 0..g_y {
                let idx = (g_x * j + i) as usize;
                let expected_cid_x = i % c_x;
                let expected_cid_y = j % c_y;
                let expected_rank = c_x * expected_cid_y + expected_cid_x;

                assert_eq!(block_x.as_slice()[idx], i);
                assert_eq!(block_y.as_slice()[idx], j);
                assert_eq!(block_z.as_slice()[idx], 0);
                assert_eq!(cluster_x.as_slice()[idx], expected_cid_x);
                assert_eq!(cluster_y.as_slice()[idx], expected_cid_y);
                assert_eq!(cluster_z.as_slice()[idx], 0);
                assert_eq!(cluster_rank.as_slice()[idx], expected_rank);
            }
        }
    }
}
