#pragma once

#define COMPLEX_FFT

#define NO_THREAD_BLOCK_CLUSTERS_ERR "Thread block clusters feature is required."

#if __CUDA_ARCH__ >= 900
#define THREAD_BLOCK_CLUSTERS
#endif