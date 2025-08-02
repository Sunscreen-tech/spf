#pragma once
#include "../math.cuh"
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
    static __device__ __inline__ constexpr float2 Get_W_value(int N, int m)
    {
        return TWIDDLES_F32[N - 2 + m];
    }

    static __device__ __inline__ constexpr float2 Get_W_value_inverse(int N, int m)
    {
        return TWIDDLES_INV_F32[N - 2 + m];
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
    static __device__ __inline__ constexpr double2 Get_W_value(int N, int m)
    {
        return TWIDDLES_F64[N - 2 + m];
    }

    static __device__ __inline__ constexpr double2 Get_W_value_inverse(int N, int m)
    {
        return TWIDDLES_INV_F64[N - 2 + m];
    }
#endif
};
