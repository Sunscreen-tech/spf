use std::os::raw::c_void;

use sunscreen_gpu_runtime::AsKernelArg;

/// An GPU ABI-compatible representation of `log2(PolynomialDegree)`.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct LogPolyDegree(pub u32);

/// An GPU ABI-compatible representation of [`crate::GlweSize`].
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct GlweSize(pub u32);

/// An GPU ABI-compatible representation of [`crate::PolynomialDegree`].
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PolynomialDegree(pub u32);

/// An GPU ABI-compatible representation of [`crate::LweDimension`].
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct LweDim(pub u32);

/// An GPU ABI-compatible representation of [`crate::LweDef`].
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct LweDef(pub LweDim);

impl From<crate::LweDef> for LweDef {
    fn from(value: crate::LweDef) -> Self {
        Self(LweDim(value.dim.0 as u32))
    }
}

impl AsKernelArg for LweDef {
    fn as_kernel_arg(&self) -> *const std::ffi::c_void {
        unsafe { std::mem::transmute(self.0.0 as u64) }
    }
}

/// An GPU ABI-compatible representation of [`crate::GlweDef`].
///
/// # Remarks
/// Only works on 64-bit architectures where pointers are 8 bytes.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct GlweDef {
    /// log2(poly degree)
    pub log_poly_degree: LogPolyDegree,

    /// The number of polynomials
    pub size: GlweSize,
}

impl From<crate::GlweDef> for GlweDef {
    fn from(value: crate::GlweDef) -> Self {
        Self {
            log_poly_degree: LogPolyDegree(value.dim.polynomial_degree.0.ilog2()),
            size: GlweSize(value.dim.size.0 as u32),
        }
    }
}

impl AsKernelArg for GlweDef {
    fn as_kernel_arg(&self) -> *const std::ffi::c_void {
        unsafe { std::mem::transmute(*self) }
    }
}

/// An GPU ABI-compatible representation of [`crate::RadixCount`].
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct RadixCount(pub u32);

/// An GPU ABI-compatible representation of [`crate::RadixLog`].
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct RadixLog(pub u32);

/// An GPU ABI-compatible representation of [`crate::RadixDecomposition`].
///
/// # Remarks
/// Only works on 64-bit architectures where pointers are 8 bytes.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RadixDecomposition {
    /// The number of digits in the decomposition
    pub count: RadixCount,

    /// log2(radix)
    pub radix_log: RadixLog,
}

impl From<crate::RadixDecomposition> for RadixDecomposition {
    fn from(value: crate::RadixDecomposition) -> Self {
        Self {
            count: RadixCount(value.count.0 as u32),
            radix_log: RadixLog(value.radix_log.0 as u32),
        }
    }
}

impl AsKernelArg for RadixDecomposition {
    fn as_kernel_arg(&self) -> *const c_void {
        unsafe { std::mem::transmute(*self) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radix_decomp_gpu() {
        assert_eq!(std::mem::size_of::<RadixDecomposition>(), 8);
        assert_eq!(std::mem::align_of::<RadixDecomposition>(), 4);

        let radix = RadixDecomposition {
            count: RadixCount(7),
            radix_log: RadixLog(42),
        };

        let [count, log] = unsafe { std::mem::transmute::<_, [u32; 2]>(radix) };

        assert_eq!(count, radix.count.0);
        assert_eq!(log, radix.radix_log.0);
    }

    #[test]
    fn params_glwe_gpu() {
        assert_eq!(std::mem::size_of::<GlweDef>(), 8);
        assert_eq!(std::mem::align_of::<GlweDef>(), 4);

        let glwe = GlweDef {
            size: GlweSize(17),
            log_poly_degree: LogPolyDegree(11),
        };

        let [log, size] = unsafe { std::mem::transmute::<_, [u32; 2]>(glwe) };

        assert_eq!(log, glwe.log_poly_degree.0);
        assert_eq!(size, glwe.size.0);
    }

    #[test]
    fn lwe_gpu() {
        assert_eq!(std::mem::size_of::<LweDef>(), 4);
        assert_eq!(std::mem::align_of::<LweDef>(), 4);

        let lwe = LweDef(LweDim(17));

        let dim = unsafe { std::mem::transmute::<_, u32>(lwe) };

        assert_eq!(dim, lwe.0.0);
    }
}
