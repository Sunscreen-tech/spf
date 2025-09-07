#pragma once
#include "ggsw.cuh"
#include "glev.cuh"
#include "glwe.cuh"
#include "polynomial.cuh"
#include "scratch.cuh"


template <typename T>
/// When using thread block clusters and this GlweCiphertextFft is in shared memory,
/// return the GLWE in another thread block's shared memory.
__device__ inline void map_remote(u32 rank) {

}