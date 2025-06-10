mod scalar;

#[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"),)))]
mod generic;
#[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"),)))]
pub use generic::*;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86_64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use x86_64::*;

use crate::FromF64;

pub trait VectorOps
where
    Self: Sized + FromF64,
{
    fn vector_add(c: &mut [Self], a: &[Self], b: &[Self]);

    fn vector_sub(c: &mut [Self], a: &[Self], b: &[Self]);

    /// Reduce a vector of f64 values mod q where q is a power of 2 and convert the result to a u64.
    fn vector_mod_pow2_q_f64(c: &mut [Self], a: &[f64], log2_q: u64);

    fn vector_next_decomp(c: &mut [Self], a: &mut [Self], radix_log: usize);

    fn vector_scalar_mad(c: &mut [Self], a: &[Self], s: Self);

    fn vector_shr(c: &mut [Self], a: &[Self], n: u32);
}
