#pragma once

#if __CUDA_ARCH__ >= 900
#error "This functionality requires cluster groups"
#endif

#include <cooperative_groups.h>

namespace cg = cooperative_groups;

// Launch with 2x3
extern "C" __global__ void cluster_rank_to_block_dim(
) {
    auto cluster = cg::this_cluster();

    auto computed_rank = cluster.block_index().x + cluster.block_index().y * cluster.dim_blocks().x;

    assert(computed_rank == cluster.block_rank());
    assert(cluster.num_blocks() == cluster.dim_blocks().x * cluster.dim_blocks().y);
}