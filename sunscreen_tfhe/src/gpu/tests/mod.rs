use num::{Complex, Float, NumCast};

mod fft;
mod negacyclic;

pub fn assert_equalish<T: Float + NumCast + std::fmt::Display>(actual: &T, expected: &T, eps: T) {
    let denom = if *actual == T::from(0.0).unwrap() {
        T::from(1.0).unwrap()
    } else {
        actual.abs()
    };

    let err = (*actual - *expected).abs() / denom;

    assert!(err < eps, "actual {actual} expected {expected}");
}

pub fn assert_complex_equalish<T: Float + NumCast + std::fmt::Display>(
    actual: &Complex<T>,
    expected: &Complex<T>,
    eps: T,
) {
    assert_equalish(&actual.re, &expected.re, eps);
    assert_equalish(&actual.im, &expected.im, eps);
}
