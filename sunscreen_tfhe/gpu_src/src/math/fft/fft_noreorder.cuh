/*
Copyright (c) 2017 Karel Adamek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#pragma once
#include "twiddles.cuh"
#include "../math.cuh"

#define WARP 32

template <typename T>
__device__ __inline__ T shfl(T *value, int par)
{
	return __shfl_sync(0xffffffff, (*value), par);
}

template <typename T>
__device__ __inline__ T shfl_xor(T *value, int par)
{
	return __shfl_xor_sync(0xffffffff, (*value), par);
}

template <typename T>
__device__ __inline__ T shfl_down(T *value, int par)
{
	return __shfl_down_sync(0xffffffff, (*value), par);
}

/// Forward decimation in time FFT.
template <class const_params, typename VecT>
__inline__ __device__ void CT_DIT_FFT_4way(VecT *s_input)
{
	using T = typename ScalarOf<VecT>::Ty;

	VecT A_DFT_value, B_DFT_value, C_DFT_value, D_DFT_value;
	VecT W;
	VecT Aftemp, Bftemp, Cftemp, Dftemp;

	int local_id, warp_id;
	int j, m_param;
	int parity, itemp;
	int A_read_index, B_read_index, C_read_index, D_read_index;
	int PoT, PoTp1, q;

	local_id = threadIdx.x & (const_params::warp - 1);
	warp_id = threadIdx.x / const_params::warp;

	//-----> FFT
	//-->
	PoT = 1;
	PoTp1 = 2;

	//--> First iteration
	itemp = local_id & 1;
	parity = (1 - itemp * 2);
	A_DFT_value = s_input[local_id + (warp_id << 2) * const_params::warp];
	B_DFT_value = s_input[local_id + (warp_id << 2) * const_params::warp + const_params::warp];
	C_DFT_value = s_input[local_id + (warp_id << 2) * const_params::warp + 2 * const_params::warp];
	D_DFT_value = s_input[local_id + (warp_id << 2) * const_params::warp + 3 * const_params::warp];

	__syncthreads();

	A_DFT_value.x = parity * A_DFT_value.x + shfl_xor(&A_DFT_value.x, 1);
	A_DFT_value.y = parity * A_DFT_value.y + shfl_xor(&A_DFT_value.y, 1);
	B_DFT_value.x = parity * B_DFT_value.x + shfl_xor(&B_DFT_value.x, 1);
	B_DFT_value.y = parity * B_DFT_value.y + shfl_xor(&B_DFT_value.y, 1);
	C_DFT_value.x = parity * C_DFT_value.x + shfl_xor(&C_DFT_value.x, 1);
	C_DFT_value.y = parity * C_DFT_value.y + shfl_xor(&C_DFT_value.y, 1);
	D_DFT_value.x = parity * D_DFT_value.x + shfl_xor(&D_DFT_value.x, 1);
	D_DFT_value.y = parity * D_DFT_value.y + shfl_xor(&D_DFT_value.y, 1);

	//--> Second through Fifth iteration (no synchronization)
	PoT = 2;
	PoTp1 = 4;
	for (q = 1; q < 5; q++)
	{
		m_param = (local_id & (PoTp1 - 1));
		itemp = m_param >> q;
		parity = ((itemp << 1) - 1);

		W = FftTwiddles<T>::Get_W_value_inverse(PoTp1, itemp * m_param);

		Aftemp.x = W.x * A_DFT_value.x - W.y * A_DFT_value.y;
		Aftemp.y = W.x * A_DFT_value.y + W.y * A_DFT_value.x;
		Bftemp.x = W.x * B_DFT_value.x - W.y * B_DFT_value.y;
		Bftemp.y = W.x * B_DFT_value.y + W.y * B_DFT_value.x;
		Cftemp.x = W.x * C_DFT_value.x - W.y * C_DFT_value.y;
		Cftemp.y = W.x * C_DFT_value.y + W.y * C_DFT_value.x;
		Dftemp.x = W.x * D_DFT_value.x - W.y * D_DFT_value.y;
		Dftemp.y = W.x * D_DFT_value.y + W.y * D_DFT_value.x;

		A_DFT_value.x = Aftemp.x + parity * shfl_xor(&Aftemp.x, PoT);
		A_DFT_value.y = Aftemp.y + parity * shfl_xor(&Aftemp.y, PoT);
		B_DFT_value.x = Bftemp.x + parity * shfl_xor(&Bftemp.x, PoT);
		B_DFT_value.y = Bftemp.y + parity * shfl_xor(&Bftemp.y, PoT);
		C_DFT_value.x = Cftemp.x + parity * shfl_xor(&Cftemp.x, PoT);
		C_DFT_value.y = Cftemp.y + parity * shfl_xor(&Cftemp.y, PoT);
		D_DFT_value.x = Dftemp.x + parity * shfl_xor(&Dftemp.x, PoT);
		D_DFT_value.y = Dftemp.y + parity * shfl_xor(&Dftemp.y, PoT);

		PoT = PoT << 1;
		PoTp1 = PoTp1 << 1;
	}

	itemp = local_id + (warp_id << 2) * const_params::warp;
	s_input[itemp] = A_DFT_value;
	s_input[itemp + const_params::warp] = B_DFT_value;
	s_input[itemp + 2 * const_params::warp] = C_DFT_value;
	s_input[itemp + 3 * const_params::warp] = D_DFT_value;

	for (q = 5; q < (const_params::fft_exp - 1); q++)
	{
		__syncthreads();
		m_param = threadIdx.x & (PoT - 1);
		j = threadIdx.x >> q;

		W = FftTwiddles<T>::Get_W_value_inverse(PoTp1, m_param);

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
	__syncthreads();
	m_param = threadIdx.x;

	W = FftTwiddles<T>::Get_W_value_inverse(PoTp1, m_param);

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
	C_DFT_value.x = Cftemp.x - W.y * Dftemp.x - W.x * Dftemp.y;
	C_DFT_value.y = Cftemp.y - W.y * Dftemp.y + W.x * Dftemp.x;
	D_DFT_value.x = Cftemp.x + W.y * Dftemp.x + W.x * Dftemp.y;
	D_DFT_value.y = Cftemp.y + W.y * Dftemp.y - W.x * Dftemp.x;

	s_input[A_read_index] = A_DFT_value;
	s_input[B_read_index] = B_DFT_value;
	s_input[C_read_index] = C_DFT_value;
	s_input[D_read_index] = D_DFT_value;

	__syncthreads();
}

template <class const_params, typename VecT>
__device__ inline void CT_DIF_FFT_4way(VecT *s_input)
{
	using T = typename ScalarOf<VecT>::Ty;

	VecT A_DFT_value, B_DFT_value, C_DFT_value, D_DFT_value;
	VecT W;
	VecT Aftemp, Bftemp, Cftemp, Dftemp;

	int local_id, warp_id;
	int j, m_param, parity;
	int A_read_index, B_read_index, C_read_index, D_read_index;
	int PoT, PoTm1, q;

	local_id = threadIdx.x & (WARP - 1);
	warp_id = threadIdx.x / WARP;

	//-----> FFT
	//-->
	PoTm1 = const_params::fft_length_half;
	PoT = const_params::fft_length;

	// Highest iteration
	m_param = threadIdx.x;
	j = 0;
	A_read_index = m_param;
	B_read_index = m_param + PoTm1;
	C_read_index = m_param + (PoTm1 >> 1);
	D_read_index = m_param + 3 * (PoTm1 >> 1);

	W = FftTwiddles<T>::Get_W_value(PoT, m_param);

	Aftemp = s_input[A_read_index];
	Bftemp = s_input[B_read_index];
	Cftemp = s_input[C_read_index];
	Dftemp = s_input[D_read_index];

	A_DFT_value.x = Aftemp.x + Bftemp.x;
	A_DFT_value.y = Aftemp.y + Bftemp.y;
	B_DFT_value.x = W.x * (Aftemp.x - Bftemp.x) - W.y * (Aftemp.y - Bftemp.y);
	B_DFT_value.y = W.x * (Aftemp.y - Bftemp.y) + W.y * (Aftemp.x - Bftemp.x);

	C_DFT_value.x = Cftemp.x + Dftemp.x;
	C_DFT_value.y = Cftemp.y + Dftemp.y;
	D_DFT_value.x = W.y * (Cftemp.x - Dftemp.x) + W.x * (Cftemp.y - Dftemp.y);
	D_DFT_value.y = W.y * (Cftemp.y - Dftemp.y) - W.x * (Cftemp.x - Dftemp.x);

	s_input[A_read_index] = A_DFT_value;
	s_input[B_read_index] = B_DFT_value;
	s_input[C_read_index] = C_DFT_value;
	s_input[D_read_index] = D_DFT_value;

	PoT = PoT >> 1;
	PoTm1 = PoTm1 >> 1;

	for (q = (const_params::fft_exp - 2); q > 4; q--)
	{
		__syncthreads();
		m_param = threadIdx.x & (PoTm1 - 1);
		j = threadIdx.x >> q;

		W = FftTwiddles<T>::Get_W_value(PoT, m_param);

		A_read_index = j * (PoT << 1) + m_param;
		B_read_index = j * (PoT << 1) + m_param + PoTm1;
		C_read_index = j * (PoT << 1) + m_param + PoT;
		D_read_index = j * (PoT << 1) + m_param + 3 * PoTm1;

		Aftemp = s_input[A_read_index];
		Bftemp = s_input[B_read_index];
		Cftemp = s_input[C_read_index];
		Dftemp = s_input[D_read_index];

		A_DFT_value.x = Aftemp.x + Bftemp.x;
		A_DFT_value.y = Aftemp.y + Bftemp.y;
		C_DFT_value.x = Cftemp.x + Dftemp.x;
		C_DFT_value.y = Cftemp.y + Dftemp.y;

		B_DFT_value.x = W.x * (Aftemp.x - Bftemp.x) - W.y * (Aftemp.y - Bftemp.y);
		B_DFT_value.y = W.x * (Aftemp.y - Bftemp.y) + W.y * (Aftemp.x - Bftemp.x);
		D_DFT_value.x = W.x * (Cftemp.x - Dftemp.x) - W.y * (Cftemp.y - Dftemp.y);
		D_DFT_value.y = W.x * (Cftemp.y - Dftemp.y) + W.y * (Cftemp.x - Dftemp.x);

		s_input[A_read_index] = A_DFT_value;
		s_input[B_read_index] = B_DFT_value;
		s_input[C_read_index] = C_DFT_value;
		s_input[D_read_index] = D_DFT_value;

		PoT = PoT >> 1;
		PoTm1 = PoTm1 >> 1;
	}

	__syncthreads();
	j = local_id + (warp_id << 2) * WARP;
	A_DFT_value = s_input[j];
	B_DFT_value = s_input[j + WARP];
	C_DFT_value = s_input[j + 2 * WARP];
	D_DFT_value = s_input[j + 3 * WARP];

	for (q = 4; q >= 0; q--)
	{
		m_param = (local_id & (PoT - 1));
		j = m_param >> q;
		parity = (1 - j * 2);
		W = FftTwiddles<T>::Get_W_value(PoT, j * (m_param - PoTm1));

		Aftemp.x = parity * A_DFT_value.x + shfl_xor(&A_DFT_value.x, PoTm1);
		Aftemp.y = parity * A_DFT_value.y + shfl_xor(&A_DFT_value.y, PoTm1);
		Bftemp.x = parity * B_DFT_value.x + shfl_xor(&B_DFT_value.x, PoTm1);
		Bftemp.y = parity * B_DFT_value.y + shfl_xor(&B_DFT_value.y, PoTm1);
		Cftemp.x = parity * C_DFT_value.x + shfl_xor(&C_DFT_value.x, PoTm1);
		Cftemp.y = parity * C_DFT_value.y + shfl_xor(&C_DFT_value.y, PoTm1);
		Dftemp.x = parity * D_DFT_value.x + shfl_xor(&D_DFT_value.x, PoTm1);
		Dftemp.y = parity * D_DFT_value.y + shfl_xor(&D_DFT_value.y, PoTm1);

		A_DFT_value.x = W.x * Aftemp.x - W.y * Aftemp.y;
		A_DFT_value.y = W.x * Aftemp.y + W.y * Aftemp.x;
		B_DFT_value.x = W.x * Bftemp.x - W.y * Bftemp.y;
		B_DFT_value.y = W.x * Bftemp.y + W.y * Bftemp.x;
		C_DFT_value.x = W.x * Cftemp.x - W.y * Cftemp.y;
		C_DFT_value.y = W.x * Cftemp.y + W.y * Cftemp.x;
		D_DFT_value.x = W.x * Dftemp.x - W.y * Dftemp.y;
		D_DFT_value.y = W.x * Dftemp.y + W.y * Dftemp.x;

		PoT = PoT >> 1;
		PoTm1 = PoTm1 >> 1;
	}

	j = local_id + (warp_id << 2) * WARP;
	s_input[j] = A_DFT_value;
	s_input[j + WARP] = B_DFT_value;
	s_input[j + 2 * WARP] = C_DFT_value;
	s_input[j + 3 * WARP] = D_DFT_value;

	__syncthreads();

#ifdef TESTING
	__syncthreads();
	int A_load_id, B_load_id, i, A_n, B_n;
	A_load_id = threadIdx.x;
	B_load_id = threadIdx.x + const_params::fft_length_quarter;
	A_n = threadIdx.x;
	B_n = threadIdx.x + const_params::fft_length_quarter;
	for (i = 1; i < const_params::fft_exp; i++)
	{
		A_n >>= 1;
		B_n >>= 1;
		A_load_id <<= 1;
		A_load_id |= A_n & 1;
		B_load_id <<= 1;
		B_load_id |= B_n & 1;
	}
	A_load_id &= const_params::fft_length - 1;
	B_load_id &= const_params::fft_length - 1;

	//-----> Scrambling input
	A_DFT_value = s_input[A_load_id];
	B_DFT_value = s_input[A_load_id + 1];
	C_DFT_value = s_input[B_load_id];
	D_DFT_value = s_input[B_load_id + 1];
	__syncthreads();
	s_input[threadIdx.x] = A_DFT_value;
	s_input[threadIdx.x + const_params::fft_length_half] = B_DFT_value;
	s_input[threadIdx.x + const_params::fft_length_quarter] = C_DFT_value;
	s_input[threadIdx.x + const_params::fft_length_three_quarters] = D_DFT_value;
	__syncthreads();
#endif
}