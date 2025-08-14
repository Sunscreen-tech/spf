use crate::{
    PolynomialDegree,
    entities::{DstArray, Polynomial},
    gpu::get_runtimes,
};

#[test]
fn can_clone_allocation() {
    let runtimes = get_runtimes();

    for _ in runtimes.iter() {
        let num_polys = 19;
        let degree = PolynomialDegree(2048);

        let mut a = DstArray::<Polynomial<u64>>::new(num_polys, degree);

        for p in a.iter_mut(degree) {
            for (i, c) in p.coeffs_mut().iter_mut().enumerate() {
                *c = i as u64;
            }
        }

        let b = a.clone();

        for (a, b) in a.iter(degree).zip(b.iter(degree)) {
            assert_eq!(a.coeffs(), b.coeffs());
        }
    }
}
