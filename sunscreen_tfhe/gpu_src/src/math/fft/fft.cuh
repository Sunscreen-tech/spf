#pragma once

#include <assert.h>
#include <stdint.h>

#include "fft_params.cuh"
#include "../math.cuh"

#define FULL_MASK 0xFFFFFFFF

__device__ __inline__ double2 Get_W_value(int N, int m)
{
	double2 ctemp;
	sincos(-PI_2 * (double)m / (double)N, &ctemp.y, &ctemp.x);
	return ctemp;
}

__device__ __inline__ double2 Get_W_value_inverse(int N, int m)
{
	double2 ctemp;
	sincos(PI_2 * (double)m / (double)N, &ctemp.y, &ctemp.x);
	return ctemp;
}

template <class const_params>
__device__ void do_SMFFT_CT_DIT(double2 *s_input)
{
	double2 A_DFT_value, B_DFT_value, C_DFT_value, D_DFT_value;
	double2 W;
	double2 Aftemp, Bftemp, Cftemp, Dftemp;

	int j, m_param;
	int parity, itemp;
	int A_read_index, B_read_index, C_read_index, D_read_index;
	int PoT, PoTp1, q;

	int local_id = threadIdx.x & (const_params::warp - 1);
	int warp_id = threadIdx.x / const_params::warp;
	A_DFT_value = s_input[local_id + (warp_id << 2) * const_params::warp];
	B_DFT_value = s_input[local_id + (warp_id << 2) * const_params::warp + const_params::warp];
	C_DFT_value = s_input[local_id + (warp_id << 2) * const_params::warp + 2 * const_params::warp];
	D_DFT_value = s_input[local_id + (warp_id << 2) * const_params::warp + 3 * const_params::warp];

	//----> FFT
	PoT = 1;
	PoTp1 = 2;

	//--> First iteration
	itemp = local_id & 1;
	parity = (1 - itemp * 2);
	
	A_DFT_value.x = parity * A_DFT_value.x + __shfl_xor_sync(FULL_MASK, A_DFT_value.x, 1);
	A_DFT_value.y = parity * A_DFT_value.y + __shfl_xor_sync(FULL_MASK, A_DFT_value.y, 1);
	B_DFT_value.x = parity * B_DFT_value.x + __shfl_xor_sync(FULL_MASK, B_DFT_value.x, 1);
	B_DFT_value.y = parity * B_DFT_value.y + __shfl_xor_sync(FULL_MASK, B_DFT_value.y, 1);
	C_DFT_value.x = parity * C_DFT_value.x + __shfl_xor_sync(FULL_MASK, C_DFT_value.x, 1);
	C_DFT_value.y = parity * C_DFT_value.y + __shfl_xor_sync(FULL_MASK, C_DFT_value.y, 1);
	D_DFT_value.x = parity * D_DFT_value.x + __shfl_xor_sync(FULL_MASK, D_DFT_value.x, 1);
	D_DFT_value.y = parity * D_DFT_value.y + __shfl_xor_sync(FULL_MASK, D_DFT_value.y, 1);

	//--> Second through Fifth iteration (no synchronization)
	PoT = 2;
	PoTp1 = 4;
	for (q = 1; q < 5; q++)
	{
		m_param = (local_id & (PoTp1 - 1));
		itemp = m_param >> q;
		parity = ((itemp << 1) - 1);

		if (const_params::fft_direction)
			W = Get_W_value_inverse(PoTp1, itemp * m_param);
		else
			W = Get_W_value(PoTp1, itemp * m_param);

		Aftemp.x = W.x * A_DFT_value.x - W.y * A_DFT_value.y;
		Aftemp.y = W.x * A_DFT_value.y + W.y * A_DFT_value.x;
		Bftemp.x = W.x * B_DFT_value.x - W.y * B_DFT_value.y;
		Bftemp.y = W.x * B_DFT_value.y + W.y * B_DFT_value.x;
		Cftemp.x = W.x * C_DFT_value.x - W.y * C_DFT_value.y;
		Cftemp.y = W.x * C_DFT_value.y + W.y * C_DFT_value.x;
		Dftemp.x = W.x * D_DFT_value.x - W.y * D_DFT_value.y;
		Dftemp.y = W.x * D_DFT_value.y + W.y * D_DFT_value.x;

		A_DFT_value.x = Aftemp.x + parity * __shfl_xor_sync(FULL_MASK, Aftemp.x, PoT);
		A_DFT_value.y = Aftemp.y + parity * __shfl_xor_sync(FULL_MASK, Aftemp.y, PoT);
		B_DFT_value.x = Bftemp.x + parity * __shfl_xor_sync(FULL_MASK, Bftemp.x, PoT);
		B_DFT_value.y = Bftemp.y + parity * __shfl_xor_sync(FULL_MASK, Bftemp.y, PoT);
		C_DFT_value.x = Cftemp.x + parity * __shfl_xor_sync(FULL_MASK, Cftemp.x, PoT);
		C_DFT_value.y = Cftemp.y + parity * __shfl_xor_sync(FULL_MASK, Cftemp.y, PoT);
		D_DFT_value.x = Dftemp.x + parity * __shfl_xor_sync(FULL_MASK, Dftemp.x, PoT);
		D_DFT_value.y = Dftemp.y + parity * __shfl_xor_sync(FULL_MASK, Dftemp.y, PoT);

		PoT = PoT << 1;
		PoTp1 = PoTp1 << 1;
	}

	itemp = local_id + (warp_id << 2) * const_params::warp;
	s_input[itemp] = A_DFT_value;
	s_input[itemp + const_params::warp] = B_DFT_value;
	s_input[itemp + 2 * const_params::warp] = C_DFT_value;
	s_input[itemp + 3 * const_params::warp] = D_DFT_value;

	if (const_params::fft_exp == 6)
	{
		__syncthreads();
		q = 5;
		m_param = threadIdx.x & (PoT - 1);
		j = threadIdx.x >> q;

		if (const_params::fft_direction)
			W = Get_W_value_inverse(PoTp1, m_param);
		else
			W = Get_W_value(PoTp1, m_param);

		A_read_index = j * (PoTp1 << 1) + m_param;
		B_read_index = j * (PoTp1 << 1) + m_param + PoT;
		C_read_index = j * (PoTp1 << 1) + m_param + PoTp1;
		D_read_index = j * (PoTp1 << 1) + m_param + 3 * PoT;

		Aftemp = s_input[A_read_index];
		Bftemp = s_input[B_read_index];
		A_DFT_value.x = Aftemp.x + W.x * Bftemp.x - W.y * Bftemp.y;
		A_DFT_value.y = Aftemp.y + W.x * Bftemp.y + W.y * Bftemp.x;
		B_DFT_value.x = Aftemp.x - W.x * Bftemp.x + W.y * Bftemp.y;
		B_DFT_value.y = Aftemp.y - W.x * Bftemp.y - W.y * Bftemp.x;

		Cftemp = s_input[C_read_index];
		Dftemp = s_input[D_read_index];
		C_DFT_value.x = Cftemp.x + W.x * Dftemp.x - W.y * Dftemp.y;
		C_DFT_value.y = Cftemp.y + W.x * Dftemp.y + W.y * Dftemp.x;
		D_DFT_value.x = Cftemp.x - W.x * Dftemp.x + W.y * Dftemp.y;
		D_DFT_value.y = Cftemp.y - W.x * Dftemp.y - W.y * Dftemp.x;

		s_input[A_read_index] = A_DFT_value;
		s_input[B_read_index] = B_DFT_value;
		s_input[C_read_index] = C_DFT_value;
		s_input[D_read_index] = D_DFT_value;

		PoT = PoT << 1;
		PoTp1 = PoTp1 << 1;
	}

	for (q = 5; q < (const_params::fft_exp - 1); q++)
	{
		__syncthreads();
		m_param = threadIdx.x & (PoT - 1);
		j = threadIdx.x >> q;

		if (const_params::fft_direction)
			W = Get_W_value_inverse(PoTp1, m_param);
		else
			W = Get_W_value(PoTp1, m_param);

		A_read_index = j * (PoTp1 << 1) + m_param;
		B_read_index = j * (PoTp1 << 1) + m_param + PoT;
		C_read_index = j * (PoTp1 << 1) + m_param + PoTp1;
		D_read_index = j * (PoTp1 << 1) + m_param + 3 * PoT;

		Aftemp = s_input[A_read_index];
		Bftemp = s_input[B_read_index];
		A_DFT_value.x = Aftemp.x + W.x * Bftemp.x - W.y * Bftemp.y;
		A_DFT_value.y = Aftemp.y + W.x * Bftemp.y + W.y * Bftemp.x;
		B_DFT_value.x = Aftemp.x - W.x * Bftemp.x + W.y * Bftemp.y;
		B_DFT_value.y = Aftemp.y - W.x * Bftemp.y - W.y * Bftemp.x;

		Cftemp = s_input[C_read_index];
		Dftemp = s_input[D_read_index];
		C_DFT_value.x = Cftemp.x + W.x * Dftemp.x - W.y * Dftemp.y;
		C_DFT_value.y = Cftemp.y + W.x * Dftemp.y + W.y * Dftemp.x;
		D_DFT_value.x = Cftemp.x - W.x * Dftemp.x + W.y * Dftemp.y;
		D_DFT_value.y = Cftemp.y - W.x * Dftemp.y - W.y * Dftemp.x;

		s_input[A_read_index] = A_DFT_value;
		s_input[B_read_index] = B_DFT_value;
		s_input[C_read_index] = C_DFT_value;
		s_input[D_read_index] = D_DFT_value;

		PoT = PoT << 1;
		PoTp1 = PoTp1 << 1;
	}

	// last iteration
	if (const_params::fft_exp > 6)
	{
		__syncthreads();
		m_param = threadIdx.x;

		if (const_params::fft_direction)
			W = Get_W_value_inverse(PoTp1, m_param);
		else
			W = Get_W_value(PoTp1, m_param);

		A_read_index = m_param;
		B_read_index = m_param + PoT;
		C_read_index = m_param + (PoT >> 1);
		D_read_index = m_param + 3 * (PoT >> 1);

		Aftemp = s_input[A_read_index];
		Bftemp = s_input[B_read_index];
		A_DFT_value.x = Aftemp.x + W.x * Bftemp.x - W.y * Bftemp.y;
		A_DFT_value.y = Aftemp.y + W.x * Bftemp.y + W.y * Bftemp.x;
		B_DFT_value.x = Aftemp.x - W.x * Bftemp.x + W.y * Bftemp.y;
		B_DFT_value.y = Aftemp.y - W.x * Bftemp.y - W.y * Bftemp.x;

		Cftemp = s_input[C_read_index];
		Dftemp = s_input[D_read_index];
		if (const_params::fft_direction)
		{
			C_DFT_value.x = Cftemp.x - W.y * Dftemp.x - W.x * Dftemp.y;
			C_DFT_value.y = Cftemp.y - W.y * Dftemp.y + W.x * Dftemp.x;
			D_DFT_value.x = Cftemp.x + W.y * Dftemp.x + W.x * Dftemp.y;
			D_DFT_value.y = Cftemp.y + W.y * Dftemp.y - W.x * Dftemp.x;
		}
		else
		{
			C_DFT_value.x = Cftemp.x + W.y * Dftemp.x + W.x * Dftemp.y;
			C_DFT_value.y = Cftemp.y + W.y * Dftemp.y - W.x * Dftemp.x;
			D_DFT_value.x = Cftemp.x - W.y * Dftemp.x - W.x * Dftemp.y;
			D_DFT_value.y = Cftemp.y - W.y * Dftemp.y + W.x * Dftemp.x;
		}

		s_input[A_read_index] = A_DFT_value;
		s_input[B_read_index] = B_DFT_value;
		s_input[C_read_index] = C_DFT_value;
		s_input[D_read_index] = D_DFT_value;
	}
}

__device__ void fft(double2 *s_input, uint32_t n)
{
	switch (n)
	{
	case 1024:
		do_SMFFT_CT_DIT<FFT_1024_forward_noreorder>(s_input);
	case 2048:
		do_SMFFT_CT_DIT<FFT_2048_forward_noreorder>(s_input);
	case 4096:
		do_SMFFT_CT_DIT<FFT_4096_forward_noreorder>(s_input);
	default:
		printf("Illegal FFT size");
		assert(false);
	}
}

__device__ void ifft(double2 *s_input, uint32_t n)
{
	switch (n)
	{
	case 1024:
		do_SMFFT_CT_DIT<FFT_1024_forward_noreorder>(s_input);
	case 2048:
		do_SMFFT_CT_DIT<FFT_2048_forward_noreorder>(s_input);
	case 4096:
		do_SMFFT_CT_DIT<FFT_4096_forward_noreorder>(s_input);
	default:
		printf("Illegal FFT size");
		assert(false);
	}
}