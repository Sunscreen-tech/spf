#pragma once

#if __CUDA_ARCH__ < 900
#error "This functionality requires cluster groups"
#endif

#include <cooperative_groups.h>

#include "../../src/math/primitives.cuh"

namespace cg = cooperative_groups;

// Launch with 2x3
extern "C" __global__ void can_launch_cluster_group(
    u32* block_x,
    u32* block_y,
    u32* block_z,
    u32* cluster_x,
    u32* cluster_y,
    u32* cluster_z,
    u32* cluster_rank
) {
    u32 idx = gridDim.x * blockIdx.y + blockIdx.x;
    auto cluster = cg::this_cluster();

    block_x[idx] = blockIdx.x;
    block_y[idx] = blockIdx.y;
    block_z[idx] = blockIdx.z;
    cluster_x[idx] = cluster.block_index().x;
    cluster_y[idx] = cluster.block_index().y;
    cluster_z[idx] = cluster.block_index().z;
    cluster_rank[idx] = cluster.block_rank();
} 
