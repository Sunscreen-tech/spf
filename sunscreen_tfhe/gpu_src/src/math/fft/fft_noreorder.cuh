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
#include <cuda/std/complex>

#include "twiddles.cuh"
#include "../math.cuh"

#define WARP 32

template <typename T>
__device__ __inline__ T shfl(T value, int par)
{
	return __shfl_sync(0xffffffff, value, par);
}

template <typename T>
__device__ __inline__ T shfl_xor(T value, int par)
{
	return __shfl_xor_sync(0xffffffff, value, par);
}

template <typename T>
__device__ __inline__ T shfl_down(T value, int par)
{
	return __shfl_down_sync(0xffffffff, value, par);
}

/// Forward decimation in time FFT.
template <class const_params, typename T>
__inline__ __device__ void CT_DIT_FFT_4way(cuda::std::complex<T> *s_input, cuda::std::complex<T> *twiddles_inv)
{
	cuda::std::complex<T> A_DFT_value, B_DFT_value, C_DFT_value, D_DFT_value;
	cuda::std::complex<T> W;
	cuda::std::complex<T> Aftemp, Bftemp, Cftemp, Dftemp;

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

	A_DFT_value.real(parity * A_DFT_value.real() + shfl_xor(A_DFT_value.real(), 1));
	A_DFT_value.imag(parity * A_DFT_value.imag() + shfl_xor(A_DFT_value.imag(), 1));
	B_DFT_value.real(parity * B_DFT_value.real() + shfl_xor(B_DFT_value.real(), 1));
	B_DFT_value.imag(parity * B_DFT_value.imag() + shfl_xor(B_DFT_value.imag(), 1));
	C_DFT_value.real(parity * C_DFT_value.real() + shfl_xor(C_DFT_value.real(), 1));
	C_DFT_value.imag(parity * C_DFT_value.imag() + shfl_xor(C_DFT_value.imag(), 1));
	D_DFT_value.real(parity * D_DFT_value.real() + shfl_xor(D_DFT_value.real(), 1));
	D_DFT_value.imag(parity * D_DFT_value.imag() + shfl_xor(D_DFT_value.imag(), 1));

	//--> Second through Fifth iteration (no synchronization)
	PoT = 2;
	PoTp1 = 4;
	for (q = 1; q < 5; q++)
	{
		m_param = (local_id & (PoTp1 - 1));
		itemp = m_param >> q;
		parity = ((itemp << 1) - 1);

		W = FftTwiddles<T>::Get_W_value_inverse(PoTp1, itemp * m_param, twiddles_inv);

		Aftemp.real(W.real() * A_DFT_value.real() - W.imag() * A_DFT_value.imag());
		Aftemp.imag(W.real() * A_DFT_value.imag() + W.imag() * A_DFT_value.real());
		Bftemp.real(W.real() * B_DFT_value.real() - W.imag() * B_DFT_value.imag());
		Bftemp.imag(W.real() * B_DFT_value.imag() + W.imag() * B_DFT_value.real());
		Cftemp.real(W.real() * C_DFT_value.real() - W.imag() * C_DFT_value.imag());
		Cftemp.imag(W.real() * C_DFT_value.imag() + W.imag() * C_DFT_value.real());
		Dftemp.real(W.real() * D_DFT_value.real() - W.imag() * D_DFT_value.imag());
		Dftemp.imag(W.real() * D_DFT_value.imag() + W.imag() * D_DFT_value.real());

		A_DFT_value.real(Aftemp.real() + parity * shfl_xor(Aftemp.real(), PoT));
		A_DFT_value.imag(Aftemp.imag() + parity * shfl_xor(Aftemp.imag(), PoT));
		B_DFT_value.real(Bftemp.real() + parity * shfl_xor(Bftemp.real(), PoT));
		B_DFT_value.imag(Bftemp.imag() + parity * shfl_xor(Bftemp.imag(), PoT));
		C_DFT_value.real(Cftemp.real() + parity * shfl_xor(Cftemp.real(), PoT));
		C_DFT_value.imag(Cftemp.imag() + parity * shfl_xor(Cftemp.imag(), PoT));
		D_DFT_value.real(Dftemp.real() + parity * shfl_xor(Dftemp.real(), PoT));
		D_DFT_value.imag(Dftemp.imag() + parity * shfl_xor(Dftemp.imag(), PoT));

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

		W = FftTwiddles<T>::Get_W_value_inverse(PoTp1, m_param, twiddles_inv);

		A_read_index = j * (PoTp1 << 1) + m_param;
		B_read_index = j * (PoTp1 << 1) + m_param + PoT;
		C_read_index = j * (PoTp1 << 1) + m_param + PoTp1;
		D_read_index = j * (PoTp1 << 1) + m_param + 3 * PoT;

		Aftemp = s_input[A_read_index];
		Bftemp = s_input[B_read_index];
		A_DFT_value.real(Aftemp.real() + W.real() * Bftemp.real() - W.imag() * Bftemp.imag());
		A_DFT_value.imag(Aftemp.imag() + W.real() * Bftemp.imag() + W.imag() * Bftemp.real());
		B_DFT_value.real(Aftemp.real() - W.real() * Bftemp.real() + W.imag() * Bftemp.imag());
		B_DFT_value.imag(Aftemp.imag() - W.real() * Bftemp.imag() - W.imag() * Bftemp.real());

		Cftemp = s_input[C_read_index];
		Dftemp = s_input[D_read_index];
		C_DFT_value.real(Cftemp.real() + W.real() * Dftemp.real() - W.imag() * Dftemp.imag());
		C_DFT_value.imag(Cftemp.imag() + W.real() * Dftemp.imag() + W.imag() * Dftemp.real());
		D_DFT_value.real(Cftemp.real() - W.real() * Dftemp.real() + W.imag() * Dftemp.imag());
		D_DFT_value.imag(Cftemp.imag() - W.real() * Dftemp.imag() - W.imag() * Dftemp.real());

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

	W = FftTwiddles<T>::Get_W_value_inverse(PoTp1, m_param, twiddles_inv);

	A_read_index = m_param;
	B_read_index = m_param + PoT;
	C_read_index = m_param + (PoT >> 1);
	D_read_index = m_param + 3 * (PoT >> 1);

	Aftemp = s_input[A_read_index];
	Bftemp = s_input[B_read_index];
	A_DFT_value.real(Aftemp.real() + W.real() * Bftemp.real() - W.imag() * Bftemp.imag());
	A_DFT_value.imag(Aftemp.imag() + W.real() * Bftemp.imag() + W.imag() * Bftemp.real());
	B_DFT_value.real(Aftemp.real() - W.real() * Bftemp.real() + W.imag() * Bftemp.imag());
	B_DFT_value.imag(Aftemp.imag() - W.real() * Bftemp.imag() - W.imag() * Bftemp.real());

	Cftemp = s_input[C_read_index];
	Dftemp = s_input[D_read_index];
	C_DFT_value.real(Cftemp.real() - W.imag() * Dftemp.real() - W.real() * Dftemp.imag());
	C_DFT_value.imag(Cftemp.imag() - W.imag() * Dftemp.imag() + W.real() * Dftemp.real());
	D_DFT_value.real(Cftemp.real() + W.imag() * Dftemp.real() + W.real() * Dftemp.imag());
	D_DFT_value.imag(Cftemp.imag() + W.imag() * Dftemp.imag() - W.real() * Dftemp.real());

	s_input[A_read_index] = A_DFT_value;
	s_input[B_read_index] = B_DFT_value;
	s_input[C_read_index] = C_DFT_value;
	s_input[D_read_index] = D_DFT_value;

	__syncthreads();
}

template <class const_params, typename T>
__device__ inline void CT_DIF_FFT_4way(cuda::std::complex<T> *s_input, cuda::std::complex<T> *twiddles)
{
	cuda::std::complex<T> A_DFT_value, B_DFT_value, C_DFT_value, D_DFT_value;
	cuda::std::complex<T> W;
	cuda::std::complex<T> Aftemp, Bftemp, Cftemp, Dftemp;

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

	A_DFT_value.real(Aftemp.real() + Bftemp.real());
	A_DFT_value.imag(Aftemp.imag() + Bftemp.imag());
	B_DFT_value.real(W.real() * (Aftemp.real() - Bftemp.real()) - W.imag() * (Aftemp.imag() - Bftemp.imag()));
	B_DFT_value.imag(W.real() * (Aftemp.imag() - Bftemp.imag()) + W.imag() * (Aftemp.real() - Bftemp.real()));

	C_DFT_value.real(Cftemp.real() + Dftemp.real());
	C_DFT_value.imag(Cftemp.imag() + Dftemp.imag());
	D_DFT_value.real(W.imag() * (Cftemp.real() - Dftemp.real()) + W.real() * (Cftemp.imag() - Dftemp.imag()));
	D_DFT_value.imag(W.imag() * (Cftemp.imag() - Dftemp.imag()) - W.real() * (Cftemp.real() - Dftemp.real()));

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

		W = FftTwiddles<T>::Get_W_value(PoT, m_param, twiddles);

		A_read_index = j * (PoT << 1) + m_param;
		B_read_index = j * (PoT << 1) + m_param + PoTm1;
		C_read_index = j * (PoT << 1) + m_param + PoT;
		D_read_index = j * (PoT << 1) + m_param + 3 * PoTm1;

		Aftemp = s_input[A_read_index];
		Bftemp = s_input[B_read_index];
		Cftemp = s_input[C_read_index];
		Dftemp = s_input[D_read_index];

		A_DFT_value.real(Aftemp.real() + Bftemp.real());
		A_DFT_value.imag(Aftemp.imag() + Bftemp.imag());
		C_DFT_value.real(Cftemp.real() + Dftemp.real());
		C_DFT_value.imag(Cftemp.imag() + Dftemp.imag());

		B_DFT_value.real(W.real() * (Aftemp.real() - Bftemp.real()) - W.imag() * (Aftemp.imag() - Bftemp.imag()));
		B_DFT_value.imag(W.real() * (Aftemp.imag() - Bftemp.imag()) + W.imag() * (Aftemp.real() - Bftemp.real()));
		D_DFT_value.real(W.real() * (Cftemp.real() - Dftemp.real()) - W.imag() * (Cftemp.imag() - Dftemp.imag()));
		D_DFT_value.imag(W.real() * (Cftemp.imag() - Dftemp.imag()) + W.imag() * (Cftemp.real() - Dftemp.real()));

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
		W = FftTwiddles<T>::Get_W_value(PoT, j * (m_param - PoTm1), twiddles);

		Aftemp.real(parity * A_DFT_value.real() + shfl_xor(A_DFT_value.real(), PoTm1));
		Aftemp.imag(parity * A_DFT_value.imag() + shfl_xor(A_DFT_value.imag(), PoTm1));
		Bftemp.real(parity * B_DFT_value.real() + shfl_xor(B_DFT_value.real(), PoTm1));
		Bftemp.imag(parity * B_DFT_value.imag() + shfl_xor(B_DFT_value.imag(), PoTm1));
		Cftemp.real(parity * C_DFT_value.real() + shfl_xor(C_DFT_value.real(), PoTm1));
		Cftemp.imag(parity * C_DFT_value.imag() + shfl_xor(C_DFT_value.imag(), PoTm1));
		Dftemp.real(parity * D_DFT_value.real() + shfl_xor(D_DFT_value.real(), PoTm1));
		Dftemp.imag(parity * D_DFT_value.imag() + shfl_xor(D_DFT_value.imag(), PoTm1));

		A_DFT_value.real(W.real() * Aftemp.real() - W.imag() * Aftemp.imag());
		A_DFT_value.imag(W.real() * Aftemp.imag() + W.imag() * Aftemp.real());
		B_DFT_value.real(W.real() * Bftemp.real() - W.imag() * Bftemp.imag());
		B_DFT_value.imag(W.real() * Bftemp.imag() + W.imag() * Bftemp.real());
		C_DFT_value.real(W.real() * Cftemp.real() - W.imag() * Cftemp.imag());
		C_DFT_value.imag(W.real() * Cftemp.imag() + W.imag() * Cftemp.real());
		D_DFT_value.real(W.real() * Dftemp.real() - W.imag() * Dftemp.imag());
		D_DFT_value.imag(W.real() * Dftemp.imag() + W.imag() * Dftemp.real());

		PoT = PoT >> 1;
		PoTm1 = PoTm1 >> 1;
	}

	j = local_id + (warp_id << 2) * WARP;
	s_input[j] = A_DFT_value;
	s_input[j + WARP] = B_DFT_value;
	s_input[j + 2 * WARP] = C_DFT_value;
	s_input[j + 3 * WARP] = D_DFT_value;

	__syncthreads();
}