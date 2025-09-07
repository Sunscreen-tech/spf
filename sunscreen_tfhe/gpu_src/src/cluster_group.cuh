#pragma once

#include "features.cuh"

#ifndef THREAD_BLOCK_CLUSTERS
#error NO_THREAD_BLOCK_CLUSTERS_ERR
#endif

#include <cooperative_groups.h>

#include "math/primitives.cuh"

namespace cg = cooperative_groups;

struct Rank {
    u32 val;

    Rank() = delete;
    __device__ explicit inline constexpr Rank(u32 val): val(val) {}
};

__device__ inline Rank get_remote_rank(const dim3 remote) {
    auto cluster = cg::this_cluster();
    auto c_size = cluster.dim_blocks();

    return Rank(c_size.x * c_size.y * remote.z + c_size.x * remote.y + remote.x);
}

template <typename T>
/// Given the PunBuf-based T in local memory, return the remote T at the given rank.
__device__ inline T map_remote(T local, const Rank rank) {
    auto cluster = cg::this_cluster();

    auto remote_ptr = cluster.map_shared_rank(local.get_ptr(), rank.val);

    return T::from_ptr(remote_ptr);
}