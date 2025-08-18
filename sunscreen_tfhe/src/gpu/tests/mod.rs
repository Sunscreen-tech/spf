use num::{Complex, Float};

mod basics;
mod entities;
mod fft;
mod homomorphisms;
// mod memory;
// mod negacyclic;
mod polynomial;
// mod signed_decomposition;
mod simd;
mod test_utils;

pub fn ulps_difference(x: f64, y: f64) -> u64 {
    // -0.0 == 0.0
    if x == y {
        return 0;
    }

    let err = if x.signum() != y.signum() {
        let x = x.abs();
        let y = y.abs();
        let x_bits = x.to_bits();
        let y_bits = y.to_bits();

        x_bits + y_bits
    } else if x == 0.0 {
        let y = y.abs();

        y.to_bits()
    } else if y == 0.0 {
        let x = x.abs();

        x.to_bits()
    } else {
        let x_bits = x.to_bits();
        let y_bits = y.to_bits();

        x_bits.abs_diff(y_bits)
    };

    if err > 100 { 100 } else { err }
}

pub fn get_inv_twisty(j: u32, n: u32) -> Complex<f64> {
    let n_float = rug::Float::with_val(256, n);
    let x = rug::Float::with_val(256, -1.0) * j / n_float.clone();
    let s = x.clone().sin_pi();
    let c = x.clone().cos_pi();

    Complex::new(c.to_f64(), s.to_f64())
}

pub fn get_twisty(j: u32, n: u32) -> Complex<f64> {
    let n_float = rug::Float::with_val(256, n);
    let x = rug::Float::with_val(256, 1.0) * j / n_float.clone();
    let s = x.clone().sin_pi();
    let c = x.clone().cos_pi();

    Complex::new(c.to_f64(), s.to_f64())
}
