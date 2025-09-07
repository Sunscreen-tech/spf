#pragma once

#include "../features.cuh"

#ifndef THREAD_BLOCK_CLUSTERS
#error "This feature requires compute capability 9.0 or later"
#endif

#include "parallel_homomorphisms.cuh"