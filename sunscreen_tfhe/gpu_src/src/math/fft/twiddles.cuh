#pragma once
#include <cuda/std/complex>

#include "../math.cuh"
#include "../primitives.cuh"
#include "fft_constants_f32.cuh"
#include "fft_constants_f64.cuh"

template <typename T>
class FftTwiddles
{
};

template <>
class FftTwiddles<float>
{
public:
#if defined(SINCOS)
    static __device__ __inline__ float2 Get_W_value(int N, int m)
    {
        float2 ctemp;
        sincos(-TAU_F * fdividef((float)m, (float)N), &ctemp.y, &ctemp.x);
        return (ctemp);
    }

    static __device__ __inline__ float2 Get_W_value_inverse(int N, int m)
    {
        float2 ctemp;
        sincos(TAU_F * fdividef((float)m, (float)N), &ctemp.y, &ctemp.x);
        return (ctemp);
    }
#elif defined(SINCOSPI)
    static __device__ __inline__ float2 Get_W_value(int N, int m)
    {
        float2 ctemp;
        sincospif(-2.0f * fdividef((float)m, (float)N), &ctemp.y, &ctemp.x);
        return (ctemp);
    }

    static __device__ __inline__ float2 Get_W_value_inverse(int N, int m)
    {
        float2 ctemp;
        sincospif(2.0 * fdividef((float)m, (float)N), &ctemp.y, &ctemp.x);
        return (ctemp);
    }
#else
    static __device__ __inline__ constexpr cuda::std::complex<f32> Get_W_value(int N, int m, cuda::std::complex<f32> *twiddles)
    {
        return twiddles[N - 2 + m];
    }

    static __device__ __inline__ constexpr cuda::std::complex<f32> Get_W_value_inverse(int N, int m, cuda::std::complex<f32> *twiddles_inv)
    {
        return twiddles_inv[N - 2 + m];
    }
#endif
};

template <>
class FftTwiddles<double>
{
public:
#if defined(SINCOS)
    static __device__ __inline__ double2 Get_W_value(int N, int m)
    {
        double2 ctemp;
        sincos(-TAU * (double)m / (double)N, &ctemp.y, &ctemp.x);
        return ctemp;
    }

    static __device__ __inline__ double2 Get_W_value_inverse(int N, int m)
    {
        double2 ctemp;
        sincos(TAU * (double)m / (double)N, &ctemp.y, &ctemp.x);
        return ctemp;
    }
#elif defined(SINCOSPI)
    static __device__ __inline__ double2 Get_W_value(int N, int m)
    {
        double2 ctemp;
        sincospi(-2.0 * (double)m / (double)N, &ctemp.y, &ctemp.x);
        return ctemp;
    }

    static __device__ __inline__ double2 Get_W_value_inverse(int N, int m)
    {
        double2 ctemp;
        sincospi(2.0 * (double)m / (double)N, &ctemp.y, &ctemp.x);
        return ctemp;
    }
#else
    static __device__ __inline__ constexpr cuda::std::complex<f64> Get_W_value(int N, int m, cuda::std::complex<f32> *twiddles)
    {
        return twiddles[N - 2 + m];
    }

    static __device__ __inline__ constexpr cuda::std::complex<f64> Get_W_value_inverse(int N, int m, cuda::std::complex<f32> *twiddles_inv)
    {
        return twiddles_inv[N - 2 + m];
    }
#endif
};
