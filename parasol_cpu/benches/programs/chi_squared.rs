use parasol_cpu::{
    FheProgram, IntoBytes, Register,
    assembly::IsaOp,
    test_utils::{buffer_from_value_80, make_computer_80, read_result},
    tomasulo::registers::RegisterName,
};

/// An implementation of the chi-squared test that does not use any
/// optimisations. The program calculates the following:
///
/// alpha: (4 * n_0 * n_2 - n_1^2)^2
/// b_1: 2(2n_0 + n_1)^2
/// b_2: (2n_0 + n_1) * (2n_2 + n_1)
/// b_3: 2(2n_2 + n_1)^2
#[allow(unused)]
pub fn chi_squared_naive_program(bit_width: u32, encrypted_computation: bool) -> Vec<IsaOp> {
    let n_0_ptr_register = RegisterName::new(0);
    let n_0_register = RegisterName::new(0);
    let n_1_ptr_register = RegisterName::new(1);
    let n_1_register = RegisterName::new(1);
    let n_2_ptr_register = RegisterName::new(2);
    let n_2_register = RegisterName::new(2);

    let two_register = RegisterName::new(3);
    let four_register = RegisterName::new(4);

    let alpha_ptr_register = RegisterName::new(5);
    let alpha_register = RegisterName::new(5);
    let b_1_ptr_register = RegisterName::new(6);
    let b_1_register = RegisterName::<Register>::new(6);
    let b_2_ptr_register = RegisterName::new(7);
    let b_2_register = RegisterName::<Register>::new(7);
    let b_3_ptr_register = RegisterName::new(8);
    let b_3_register = RegisterName::<Register>::new(8);

    let n_1_sq_register = RegisterName::new(9);
    let two_n_0_plus_n_1_register = RegisterName::new(10);

    vec![
        IsaOp::BindReadOnly(n_0_ptr_register, 0, encrypted_computation),
        IsaOp::BindReadOnly(n_1_ptr_register, 1, encrypted_computation),
        IsaOp::BindReadOnly(n_2_ptr_register, 2, encrypted_computation),
        IsaOp::LoadI(two_register, 2, bit_width),
        IsaOp::LoadI(four_register, 4, bit_width),
        IsaOp::BindReadWrite(alpha_ptr_register, 3, encrypted_computation),
        IsaOp::BindReadWrite(b_1_ptr_register, 4, encrypted_computation),
        IsaOp::BindReadWrite(b_2_ptr_register, 5, encrypted_computation),
        IsaOp::BindReadWrite(b_3_ptr_register, 6, encrypted_computation),
        IsaOp::Load(n_0_register, n_0_ptr_register, bit_width),
        IsaOp::Load(n_1_register, n_1_ptr_register, bit_width),
        IsaOp::Load(n_2_register, n_2_ptr_register, bit_width),
        //
        // alpha: (4 * n_0 * n_2 - n_1^2)^2
        // n_0 * n_2
        IsaOp::Mul(alpha_register, n_0_register, n_2_register),
        // 4 * (n_0 * n_2)
        IsaOp::Mul(alpha_register, four_register, alpha_register),
        // n_1^2
        IsaOp::Mul(n_1_sq_register, n_1_register, n_1_register),
        // 4 * (n_0 * n_2) - n_1^2
        IsaOp::Sub(alpha_register, alpha_register, n_1_sq_register),
        // (4 * (n_0 * n_2) - n_1^2)^2
        IsaOp::Mul(alpha_register, alpha_register, alpha_register),
        //
        // b_1: 2(2n_0 + n_1)^2
        // 2 * n_0
        IsaOp::Mul(b_1_register, two_register, n_0_register),
        // 2n_0 + n_1
        IsaOp::Add(b_1_register, b_1_register, n_1_register),
        // (2n_0 + n_1)^2
        IsaOp::Mul(b_1_register, b_1_register, b_1_register),
        // 2(2n_0 + n_1)^2
        IsaOp::Mul(b_1_register, two_register, b_1_register),
        //
        // b_2: (2n_0 + n_1) * (2n_2 + n_1)
        // 2 * n_2
        IsaOp::Mul(b_2_register, two_register, n_2_register),
        // 2n_2 + n_1
        IsaOp::Add(b_2_register, b_2_register, n_1_register),
        // 2n_0
        IsaOp::Mul(two_n_0_plus_n_1_register, two_register, n_0_register),
        // 2n_0 + n_1
        IsaOp::Add(
            two_n_0_plus_n_1_register,
            two_n_0_plus_n_1_register,
            n_1_register,
        ),
        // (2n_0 + n_1) * (2n_2 + n_1)
        IsaOp::Mul(b_2_register, two_n_0_plus_n_1_register, b_2_register),
        //
        // b_3: 2(2n_2 + n_1)^2
        // 2 * n_2
        IsaOp::Mul(b_3_register, two_register, n_2_register),
        // 2n_2 + n_1
        IsaOp::Add(b_3_register, b_3_register, n_1_register),
        // (2n_2 + n_1)^2
        IsaOp::Mul(b_3_register, b_3_register, b_3_register),
        // 2(2n_2 + n_1)^2
        IsaOp::Mul(b_3_register, two_register, b_3_register),
        //
        // Output the results
        IsaOp::Store(alpha_ptr_register, alpha_register, bit_width),
        IsaOp::Store(b_1_ptr_register, b_1_register, bit_width),
        IsaOp::Store(b_2_ptr_register, b_2_register, bit_width),
        IsaOp::Store(b_3_ptr_register, b_3_register, bit_width),
    ]
}

/// An implementation of the chi-squared test that uses optimisations to reduce
/// the number of operations. The program calculates the following:
///
/// alpha: (4 * n_0 * n_2 - n_1^2)^2
/// b_1: 2(2n_0 + n_1)^2
/// b_2: (2n_0 + n_1) * (2n_2 + n_1)
/// b_3: 2(2n_2 + n_1)^2
///
/// but using fewer operations:
///
/// x = n_0 + n_0 + n_1
/// y = n_2 + n_2 + n_1
/// alpha = (4 * n_0 * n_2 - n_1^2)^2
/// b_1 = 2 * x * x
/// b_2 = x * y
/// b_3 = 2 * y * y
///
/// The constants are implemented as repeated additions.
pub fn chi_squared_optimised_program(bit_width: u32, encrypted_computation: bool) -> Vec<IsaOp> {
    let n_0_ptr_register = RegisterName::new(0);
    let n_0_register = RegisterName::new(0);
    let n_1_ptr_register = RegisterName::new(1);
    let n_1_register = RegisterName::new(1);
    let n_2_ptr_register = RegisterName::new(2);
    let n_2_register = RegisterName::new(2);

    let two_register = RegisterName::new(3);
    let four_register = RegisterName::new(4);

    let alpha_ptr_register = RegisterName::new(5);
    let alpha_register = RegisterName::new(5);
    let b_1_ptr_register = RegisterName::new(6);
    let b_1_register = RegisterName::<Register>::new(6);
    let b_2_ptr_register = RegisterName::new(7);
    let b_2_register = RegisterName::<Register>::new(7);
    let b_3_ptr_register = RegisterName::new(8);
    let b_3_register = RegisterName::<Register>::new(8);

    let x_register = RegisterName::new(9);
    let y_register = RegisterName::new(10);
    let n_0_n_2_register = RegisterName::new(11);
    let n_1_sq_register = RegisterName::new(12);

    vec![
        IsaOp::BindReadOnly(n_0_ptr_register, 0, encrypted_computation),
        IsaOp::BindReadOnly(n_1_ptr_register, 1, encrypted_computation),
        IsaOp::BindReadOnly(n_2_ptr_register, 2, encrypted_computation),
        IsaOp::LoadI(two_register, 2, bit_width),
        IsaOp::LoadI(four_register, 4, bit_width),
        IsaOp::BindReadWrite(alpha_ptr_register, 3, encrypted_computation),
        IsaOp::BindReadWrite(b_1_ptr_register, 4, encrypted_computation),
        IsaOp::BindReadWrite(b_2_ptr_register, 5, encrypted_computation),
        IsaOp::BindReadWrite(b_3_ptr_register, 6, encrypted_computation),
        IsaOp::Load(n_0_register, n_0_ptr_register, bit_width),
        IsaOp::Load(n_1_register, n_1_ptr_register, bit_width),
        IsaOp::Load(n_2_register, n_2_ptr_register, bit_width),
        //
        // x = n_0 + n_0 + n_1
        IsaOp::Add(x_register, n_0_register, n_0_register),
        IsaOp::Add(x_register, x_register, n_1_register),
        //
        // y = n_2 + n_2 + n_1
        IsaOp::Add(y_register, n_2_register, n_2_register),
        IsaOp::Add(y_register, y_register, n_1_register),
        //
        // alpha
        // n_0 * n_2
        IsaOp::Mul(n_0_n_2_register, n_0_register, n_2_register),
        // n_0_n_2 = n_0_n_2 + n_0_n_2
        IsaOp::Add(n_0_n_2_register, n_0_n_2_register, n_0_n_2_register),
        // n_0_n_2 = n_0_n_2 + n_0_n_2
        IsaOp::Add(n_0_n_2_register, n_0_n_2_register, n_0_n_2_register),
        // n_1_sq = n_1 * n_1
        IsaOp::Mul(n_1_sq_register, n_1_register, n_1_register),
        // alpha = n_0_n_2 - n_1_sq
        IsaOp::Sub(alpha_register, n_0_n_2_register, n_1_sq_register),
        // alpha = alpha * alpha
        IsaOp::Mul(alpha_register, alpha_register, alpha_register),
        //
        // b_1 = x * x
        IsaOp::Mul(b_1_register, x_register, x_register),
        // b_1 = b_1 + b_1
        IsaOp::Add(b_1_register, b_1_register, b_1_register),
        //
        // b_2 = x * y
        IsaOp::Mul(b_2_register, x_register, y_register),
        //
        // b_3 = y * y
        IsaOp::Mul(b_3_register, y_register, y_register),
        // b_3 = b_3 + b_3
        IsaOp::Add(b_3_register, b_3_register, b_3_register),
        //
        // Output the results
        IsaOp::Store(alpha_ptr_register, alpha_register, bit_width),
        IsaOp::Store(b_1_ptr_register, b_1_register, bit_width),
        IsaOp::Store(b_2_ptr_register, b_2_register, bit_width),
        IsaOp::Store(b_3_ptr_register, b_3_register, bit_width),
    ]
}

/// Run a chi-squared program on the given values.
#[allow(unused)]
pub fn chi_squared_runner<T>(
    n_0: T,
    n_1: T,
    n_2: T,
    zero: T,
    encrypted_computation: bool,
    program: &FheProgram,
) -> (T, T, T, T)
where
    T: IntoBytes + Copy,
{
    let (mut proc, enc) = make_computer_80();

    let buffer_0 = buffer_from_value_80(n_0, &enc, encrypted_computation);
    let buffer_1 = buffer_from_value_80(n_1, &enc, encrypted_computation);
    let buffer_2 = buffer_from_value_80(n_2, &enc, encrypted_computation);

    let output_buffer_0 = buffer_from_value_80(zero, &enc, encrypted_computation);
    let output_buffer_1 = buffer_from_value_80(zero, &enc, encrypted_computation);
    let output_buffer_2 = buffer_from_value_80(zero, &enc, encrypted_computation);
    let output_buffer_3 = buffer_from_value_80(zero, &enc, encrypted_computation);

    let params = [
        buffer_0.clone(),
        buffer_1.clone(),
        buffer_2.clone(),
        output_buffer_0.clone(),
        output_buffer_1.clone(),
        output_buffer_2.clone(),
        output_buffer_3.clone(),
    ];

    proc.run_program(
        program,
        &[
            buffer_0,
            buffer_1,
            buffer_2,
            output_buffer_0,
            output_buffer_1,
            output_buffer_2,
            output_buffer_3,
        ],
    )
    .unwrap();

    let alpha = read_result(&params[3], &enc, encrypted_computation);
    let b_1 = read_result(&params[4], &enc, encrypted_computation);
    let b_2 = read_result(&params[5], &enc, encrypted_computation);
    let b_3 = read_result(&params[6], &enc, encrypted_computation);

    (alpha, b_1, b_2, b_3)
}

#[cfg(test)]
mod tests {
    use std::ops::{Add, Mul, Sub};

    use crate::programs::chi_squared::{
        chi_squared_naive_program, chi_squared_optimised_program, chi_squared_runner,
    };

    fn _init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn _basic_chi_squared<T>(n_0: T, n_1: T, n_2: T, two: T, four: T) -> (T, T, T, T)
    where
        T: Add<T, Output = T> + Mul<T, Output = T> + Sub<T, Output = T> + Copy,
    {
        let a = four * n_0 * n_2 - n_1 * n_1;
        let a_sq = a * a;

        let b_1 = two * n_0 + n_1;
        let b_1_sq = two * b_1 * b_1;

        let b_2 = (two * n_0 + n_1) * (two * n_2 + n_1);
        let b_3 = two * (two * n_2 + n_1) * (two * n_2 + n_1);

        (a_sq, b_1_sq, b_2, b_3)
    }

    fn _test_chi_squared(encrypted_computation: bool, optimised: bool) {
        type Unsigned = u8;
        let bit_width = 8;

        // Numbers chosen so that the result does not exceed 255
        let n_0: Unsigned = 2;
        let n_1: Unsigned = 3;
        let n_2: Unsigned = 3;
        let zero: Unsigned = 0;
        let two: Unsigned = 2;
        let four: Unsigned = 4;

        // prevent overflow
        assert!(four * n_0 * n_2 > n_1 * n_1);

        let program = if optimised {
            chi_squared_optimised_program(bit_width, encrypted_computation)
        } else {
            chi_squared_naive_program(bit_width, encrypted_computation)
        };

        let (a, b_1, b_2, b_3) = _basic_chi_squared(n_0, n_1, n_2, two, four);

        // Time this
        let (a_enc, b_1_enc, b_2_enc, b_3_enc) =
            chi_squared_runner(n_0, n_1, n_2, zero, encrypted_computation, &program.into());

        assert_eq!(a, a_enc);
        assert_eq!(b_1, b_1_enc);
        assert_eq!(b_2, b_2_enc);
        assert_eq!(b_3, b_3_enc);
    }

    #[test]
    fn chi_squared_plain_naive() {
        init();
        test_chi_squared(false, false);
    }

    #[test]
    fn chi_squared_encrypted_naive() {
        init();
        test_chi_squared(true, false);
    }

    #[test]
    fn chi_squared_plain_optimised() {
        init();
        test_chi_squared(false, true);
    }

    #[test]
    fn chi_squared_encrypted_optimised() {
        init();
        test_chi_squared(true, true);
    }
}
