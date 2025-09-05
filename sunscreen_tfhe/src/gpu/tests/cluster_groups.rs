use sunscreen_gpu_runtime::{launch_kernel_cg, ComputeVersion, DeviceId};

use crate::gpu::get_runtimes;

#[test]
fn can_launch_cluster() {
    const COMPUTE_CAPABILITY_9_0: ComputeVersion = ComputeVersion { major: 9, minor: 0 };

    let runtimes = get_runtimes();

    for r in runtimes.iter() {
        if r.get_device_attributes(DeviceId(0)).compute_version < COMPUTE_CAPABILITY_9_0 {
            return;
        }

        let stream = r.make_stream(DeviceId(0)).unwrap();

        let tpb = 64;
        let g_x = 6 * tpb;
        let g_y = 12;

        let c_x = 2;
        let c_y = 3;


        launch_kernel_cg!(
            (((g_x, tpb), (g_y, 1)))
            ((c_x, c_y))
            ("cluster_rank_to_block_dim")
            (r, stream, 0)
        );

        stream.wait().unwrap();
    }
}
