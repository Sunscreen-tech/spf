use std::{cell::RefCell, ops::{Deref, DerefMut}, sync::{atomic::{AtomicBool, AtomicUsize, Ordering}, Mutex}};

use crate::sys::{
    new_reim_fft_precomp, new_reim_ifft_precomp, reim_fft, reim_ifft, REIM_FFT_PRECOMP, REIM_IFFT_PRECOMP
};

mod sys {
    #![allow(non_snake_case)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]
    #![allow(non_camel_case_types)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub struct Fft {
    fwd: *mut REIM_FFT_PRECOMP,
    rev: *mut REIM_IFFT_PRECOMP,
}

impl Fft {
    pub fn new(n: u32) -> Self {
        let fwd = unsafe { new_reim_fft_precomp(n, 0) };
        let rev = unsafe { new_reim_ifft_precomp(n, 0) };

        Self { fwd, rev }
    }

    pub fn fft_inplace(&self, data: &mut [f64]) {
        // This requirement is an implementation detail of spqlios
        assert!(data.as_ptr().align_offset(64) == 0, "FFT inputs must be 64-byte aligned");

        unsafe { reim_fft(self.fwd, data.as_mut_ptr()) };
    }

    pub fn ifft_inplace(&self, data: &mut [f64]) {
        // This requirement is an implementation detail of spqlios
        assert!(data.as_ptr().align_offset(64) == 0, "FFT inputs must be 64-byte aligned");

        unsafe { reim_ifft(self.rev, data.as_mut_ptr()) };
    }
}

unsafe impl Sync for Fft {}
unsafe impl Send for Fft {}

#[cfg(test)]
mod tests {
    use aligned_vec::avec;

    use super::*;

    #[test]
    fn can_roundtrip() {
        let fft = Fft::new(16);

        let x = (0..16).map(|x| x as f64).collect::<Vec<_>>();
        let mut y = avec![[64]| 0.0f64; 16];

        (*y).clone_from_slice(&x);

        fft.fft_inplace(&mut y);
        fft.ifft_inplace(&mut y);

        assert_eq!(x.as_slice(), &*y);
    }
}