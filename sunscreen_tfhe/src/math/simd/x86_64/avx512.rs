use std::arch::asm;

use num::Complex;

/// Compute vector `c += a * b` over `&[Complex<f64>]`.
/// This function is very unsafe.
///
/// # Safety
/// c, a, b must be aligned to a 512-bit boundary. The program will otherwise bus error
/// and crash.
///
/// the lengths of c, a, and b must be the equal or UB may result.
/// the lengths of c, a, and b must be a multiple of 8 or UB will result.
#[inline(always)]
pub unsafe fn complex_mad_avx_512_unchecked(
    c: &mut [Complex<f64>],
    a: &[Complex<f64>],
    b: &[Complex<f64>],
) {
    let mut i = 0;

    // Complex<T> is declared as repr(C), so the location of re and im are guaranteed
    // at address offsets 0 and 8 for Complex<f64>. This allows us to treat
    // &[Complex<f64>] as &[f64] for the below asm snippet.
    let a_ptr = a.as_ptr() as *const f64;
    let b_ptr = b.as_ptr() as *const f64;
    let c_ptr = c.as_ptr() as *mut f64;

    // Each complex is 2 f64 values.
    while i < 2 * c.len() {
        // AVX512 isn't currently available on stable, so write some goddamn assembly
        // code I guess ¯\_(ツ)_/¯
        //
        // This snippet reads 2 vectors of 4 complex numbers from a, b, c and computes
        // stores the complex multiply-add result to c. Thus, it iterates over 16 f64
        // elements from each vector at a time.
        unsafe {
            asm!(
                // Load 2 __m512d of Complex<f64> from a
                "vmovapd zmm0, [{a_ptr}+8*{i}]",
                "vmovapd zmm1, [{a_ptr}+8*{i}+64]",
                "vshufpd zmm2, zmm0, zmm1, $0",   // Extract the re(a) into zmm2
                "vshufpd zmm3, zmm0, zmm1, $255", // Extract the im(a) into zmm3
                // Load 2 __m512d of Complex<f64> from b
                "vmovapd zmm0, [{b_ptr}+8*{i}]",
                "vmovapd zmm1, [{b_ptr}+8*{i}+64]",
                "vshufpd zmm4, zmm0, zmm1, $0",   // Extract the re(b) into zmm4
                "vshufpd zmm5, zmm0, zmm1, $255", // Extract the im(b) into zmm5
                // Load 2 __m512d of Complex<f64> from c
                "vmovapd zmm0, [{c_ptr}+8*{i}]",
                "vmovapd zmm1, [{c_ptr}+8*{i}+64]",
                "vshufpd zmm6, zmm0, zmm1, $0",   // Extract the re(c) into zmm6
                "vshufpd zmm7, zmm0, zmm1, $255", // Extract the im(c) into zmm7
                "vfmadd231pd zmm6, zmm2, zmm4",   // re(c) += re(a) * re(b)
                "vfmadd231pd zmm7, zmm2, zmm5",   // im(c) += re(a) * im(b)
                "vfnmadd231pd zmm6, zmm3, zmm5",  // re(c) -= im(a) * im(b)
                "vfmadd231pd zmm7, zmm3, zmm4",   // im(c) += im(a) * re(b)
                "vshufpd zmm0, zmm6, zmm7, $0",   // Repack the lower 4 Complex<f64>s
                "vshufpd zmm1, zmm6, zmm7, $255", // Repack the upper 4 Complex<f64>s
                "vmovapd [{c_ptr}+8*{i}], zmm0",    // Write the repacked values back.
                "vmovapd [{c_ptr}+8*{i}+64], zmm1", // Write the repacked values back.
                a_ptr = in(reg) a_ptr,
                b_ptr = in(reg) b_ptr,
                c_ptr = in(reg) c_ptr,
                i = in(reg) i,
                out("zmm0") _, // Indicate our clobbers
                out("zmm1") _,
                out("zmm2") _,
                out("zmm3") _,
                out("zmm4") _,
                out("zmm5") _,
                out("zmm6") _,
                out("zmm7") _,
            );
        }

        i += 16;
    }
}

/// Compute vector `c += a * b` over `&[Complex<f64>]`.
/// This function is very unsafe.
///
/// # Safety
/// c, a, b must be aligned to a 512-bit boundary. The program will otherwise bus error
/// and crash.
///
/// the lengths of c, a, and b must be the equal or UB may result.
/// the lengths of c, a, and b must be a multiple of 8 or UB will result.
#[inline(always)]
pub unsafe fn realimag_mad_avx_512_unchecked(c: &mut [f64], a: &[f64], b: &[f64]) {
    let mut i = 0;
    let n = a.len();
    let n_div_2 = n / 2;

    // Complex<T> is declared as repr(C), so the location of re and im are guaranteed
    // at address offsets 0 and 8 for Complex<f64>. This allows us to treat
    // &[Complex<f64>] as &[f64] for the below asm snippet.
    let (a_re, a_im) = a.split_at(n_div_2);
    let (b_re, b_im) = b.split_at(n_div_2);
    let (c_re, c_im) = c.split_at_mut(n_div_2);

    let a_re_ptr = a_re.as_ptr() as *const f64;
    let b_re_ptr = b_re.as_ptr() as *const f64;
    let c_re_ptr = c_re.as_ptr() as *mut f64;

    let a_im_ptr = a_im.as_ptr() as *const f64;
    let b_im_ptr = b_im.as_ptr() as *const f64;
    let c_im_ptr = c_im.as_ptr() as *mut f64;

    // Each complex is 2 f64 values.
    while i < n_div_2 {
        // AVX512 isn't currently available on stable, so write some goddamn assembly
        // code I guess ¯\_(ツ)_/¯
        //
        // This snippet reads 2 vectors of 4 complex numbers from a, b, c and computes
        // stores the complex multiply-add result to c. Thus, it iterates over 16 f64
        // elements from each vector at a time.
        unsafe {
            asm!(
                // Load 2 __m512d of Complex<f64> from a
                "vmovapd zmm0, [{a_re_ptr}+8*{i}]",
                "vmovapd zmm1, [{a_im_ptr}+8*{i}]",
                // Load 2 __m512d of Complex<f64> from b
                "vmovapd zmm2, [{b_re_ptr}+8*{i}]",
                "vmovapd zmm3, [{b_im_ptr}+8*{i}]",
                // Load 2 __m512d of Complex<f64> from c
                "vmovapd zmm4, [{c_re_ptr}+8*{i}]",
                "vmovapd zmm5, [{c_im_ptr}+8*{i}]",
                "vfmadd231pd zmm4, zmm0, zmm2",   // re(c) += re(a) * re(b)
                "vfmadd231pd zmm5, zmm0, zmm3",   // im(c) += re(a) * im(b)
                "vfnmadd231pd zmm4, zmm1, zmm3",  // re(c) -= im(a) * im(b)
                "vfmadd231pd zmm5, zmm1, zmm2",   // im(c) += im(a) * re(b)
                "vmovapd [{c_re_ptr}+8*{i}], zmm4",    // Write the repacked values back.
                "vmovapd [{c_im_ptr}+8*{i}], zmm5", // Write the repacked values back.
                a_re_ptr = in(reg) a_re_ptr,
                b_re_ptr = in(reg) b_re_ptr,
                c_re_ptr = in(reg) c_re_ptr,
                a_im_ptr = in(reg) a_im_ptr,
                b_im_ptr = in(reg) b_im_ptr,
                c_im_ptr = in(reg) c_im_ptr,
                i = in(reg) i,
                out("zmm0") _, // Indicate our clobbers
                out("zmm1") _,
                out("zmm2") _,
                out("zmm3") _,
                out("zmm4") _,
                out("zmm5") _,
            );
        }

        i += 8;
    }
}

/// Compute vector `c += a * b` over `&[Complex<f64>]`.
/// This function is very unsafe.
///
/// # Safety
/// c, a, b must be aligned to a 512-bit boundary. The program will otherwise bus error
/// and crash.
///
/// the lengths of c, a, and b must be the equal or UB may result.
/// the lengths of c, a, and b must be a multiple of 8 or UB will result.
#[inline(always)]
pub unsafe fn complex_msub_avx_512_unchecked(
    c: &mut [Complex<f64>],
    a: &[Complex<f64>],
    b: &[Complex<f64>],
) {
    let mut i = 0;

    // Complex<T> is declared as repr(C), so the location of re and im are guaranteed
    // at address offsets 0 and 8 for Complex<f64>. This allows us to treat
    // &[Complex<f64>] as &[f64] for the below asm snippet.
    let a_ptr = a.as_ptr() as *const f64;
    let b_ptr = b.as_ptr() as *const f64;
    let c_ptr = c.as_ptr() as *mut f64;

    // Each complex is 2 f64 values.
    while i < 2 * c.len() {
        // AVX512 isn't currently available on stable, so write some goddamn assembly
        // code I guess ¯\_(ツ)_/¯
        //
        // This snippet reads 2 vectors of 4 complex numbers from a, b, c and computes
        // stores the complex multiply-add result to c. Thus, it iterates over 16 f64
        // elements from each vector at a time.
        unsafe {
            asm!(
                // Load 2 __m512d of Complex<f64> from a
                "vmovapd zmm0, [{a_ptr}+8*{i}]",
                "vmovapd zmm1, [{a_ptr}+8*{i}+64]",
                "vshufpd zmm2, zmm0, zmm1, $0",   // Extract the re(a) into zmm2
                "vshufpd zmm3, zmm0, zmm1, $255", // Extract the im(a) into zmm3
                // Load 2 __m512d of Complex<f64> from b
                "vmovapd zmm0, [{b_ptr}+8*{i}]",
                "vmovapd zmm1, [{b_ptr}+8*{i}+64]",
                "vshufpd zmm4, zmm0, zmm1, $0",   // Extract the re(b) into zmm4
                "vshufpd zmm5, zmm0, zmm1, $255", // Extract the im(b) into zmm5
                // Load 2 __m512d of Complex<f64> from c
                "vmovapd zmm0, [{c_ptr}+8*{i}]",
                "vmovapd zmm1, [{c_ptr}+8*{i}+64]",
                "vshufpd zmm6, zmm0, zmm1, $0",   // Extract the re(c) into zmm6
                "vshufpd zmm7, zmm0, zmm1, $255", // Extract the im(c) into zmm7
                "vfnmadd231pd zmm6, zmm2, zmm4",   // re(c) -= re(a) * re(b)
                "vfnmadd231pd zmm7, zmm2, zmm5",   // im(c) -= re(a) * im(b)
                "vfmadd231pd zmm6, zmm3, zmm5",  // re(c) += im(a) * im(b)
                "vfnmadd231pd zmm7, zmm3, zmm4",   // im(c) -= im(a) * re(b)
                "vshufpd zmm0, zmm6, zmm7, $0",   // Repack the lower 4 Complex<f64>s
                "vshufpd zmm1, zmm6, zmm7, $255", // Repack the upper 4 Complex<f64>s
                "vmovapd [{c_ptr}+8*{i}], zmm0",    // Write the repacked values back.
                "vmovapd [{c_ptr}+8*{i}+64], zmm1", // Write the repacked values back.
                a_ptr = in(reg) a_ptr,
                b_ptr = in(reg) b_ptr,
                c_ptr = in(reg) c_ptr,
                i = in(reg) i,
                out("zmm0") _, // Indicate our clobbers
                out("zmm1") _,
                out("zmm2") _,
                out("zmm3") _,
                out("zmm4") _,
                out("zmm5") _,
                out("zmm6") _,
                out("zmm7") _,
            );
        }

        i += 16;
    }
}

pub fn vector_scalar_mad(c: &mut [u64], a: &[u64], s: u64) {
    let mut i = 0;

    // Complex<T> is declared as repr(C), so the location of re and im are guaranteed
    // at address offsets 0 and 8 for Complex<f64>. This allows us to treat
    // &[Complex<f64>] as &[f64] for the below asm snippet.
    let a_ptr = a.as_ptr() as *const f64;
    let c_ptr = c.as_ptr() as *mut f64;

    #[repr(C, align(64))]
    struct AlignedArray([i64; 8]);

    let s = s as i64;
    let s = AlignedArray([s, s, s, s, s, s, s, s]);
    let s_ptr = s.0.as_ptr();

    // Each complex is 2 f64 values.
    while i < c.len() {
        unsafe {
            asm!(
                // TODO: Move loading s outside the loop.
                "vmovdqa64 zmm7, [{s_ptr}]",

                // Load 2 __m512d of u64 from a
                "vmovdqa64 zmm0, [{a_ptr}+8*{i}]",
                "vmovdqa64 zmm1, [{a_ptr}+8*{i}+64]",

                // Load 2 __m512d of u64 from c
                "vmovdqa64 zmm2, [{c_ptr}+8*{i}]",
                "vmovdqa64 zmm3, [{c_ptr}+8*{i}+64]",

                "vpmullq zmm4, zmm0, zmm7", // multiply 64-bit words in zmm0 and zmm2
                "vpmullq zmm5, zmm1, zmm7", // multiply 64-bit words in zmm1 and zmm3

                "vpaddq zmm2, zmm2, zmm4", // Add zmm0 scaled by s
                "vpaddq zmm3, zmm3, zmm5", // Add zmm1 scaled by s

                "vmovdqa64 [{c_ptr}+8*{i}], zmm2",
                "vmovdqa64 [{c_ptr}+8*{i}+64], zmm3",

                a_ptr = in(reg) a_ptr,
                c_ptr = in(reg) c_ptr,
                i = in(reg) i,
                s_ptr = in(reg) s_ptr,
                out("zmm0") _, // Indicate our clobbers
                out("zmm1") _,
                out("zmm2") _,
                out("zmm3") _,
                out("zmm4") _,
                out("zmm5") _,
                out("zmm7") _,
            );
        }

        i += 16;
    }
}

#[cfg(test)]
mod tests {
    use aligned_vec::avec;

    use crate::{
        dst::{dst_from_iter, dst_from_slice},
        simd::{scalar, x86_64::avx_512_available},
    };

    use super::*;

    #[test]
    fn can_vector_scalar_mad() {
        // Skip the test if the current hardware can't run it.
        if avx_512_available() {
            let a = dst_from_slice(&(0..64u64).collect::<Vec<_>>());
            let s = 123u32;
            let mut c = dst_from_slice(&vec![0; 64]);
            let expected = dst_from_iter(c.iter().zip(a.iter()).map(|(c, a)| c + a * s as u64));

            vector_scalar_mad(&mut c, &a, s as u64);

            assert_eq!(c, expected);
        }
    }

    #[test]
    fn can_realimag_mad() {
        // Skip the test if the current hardware can't run it.
        if avx_512_available() {
            let mut a = avec![[64]| 0.0f64; 2048];
            let mut b = a.clone();
            let mut actual = a.clone();

            for i in 0..2048 {
                a[i] = i as f64;
                b[i] = 2.0 * i as f64;
                actual[i] = 3.0 * i as f64;
            }

            let mut expected = actual.clone();

            unsafe {
                realimag_mad_avx_512_unchecked(&mut actual, &a, &b);
            }

            scalar::realimag_mad(&mut expected, &a, &b);

            assert_eq!(expected, actual);
        }
    }
}
