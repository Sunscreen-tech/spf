use rand::{RngCore, thread_rng};

use crate::{
    proc::IsaOp,
    proc::program::FheProgram,
    test_utils::{buffer_from_value_80, make_computer_80, read_result},
    tomasulo::registers::RegisterName,
};

// Implements this program:
// [[clang::fhe_circuit]] void cmux(
//     [[clang::encrypted]] uX_ptr bound_ptr,
//     [[clang::encrypted]] uX_ptr a_ptr,
//     [[clang::encrypted]] uX_ptr b_ptr,
//     [[clang::encrypted]] uX_ptr output_ptr
// ) {
//     uX bound = *bound_ptr;
//     uX a = *a_ptr;
//     uX b = *b_ptr;
//
//     *output_ptr = (bound > 10) ? a : b;
// }
// ber     p0, 0
// ldr     r0, p0
// ldi     r1, 10
// gt      r0, r0, r1
// ber     p2, 2
// ldr     r1, p2
// ber     p1, 1
// ldr     r2, p1
// cmux    r0, r0, r2, r1
// berw    p3, 3
// str     p3, r0
// ret
// where ber is BindReadOnly, ldr is Load, ldi is LoadImmediate, gt is GreaterThan, berw is BindReadWrite, str is Store, and ret is Return
fn cmux_test_program(encrypted: bool) -> [IsaOp; 11] {
    [
        IsaOp::BindReadOnly(RegisterName::new(0), 0, encrypted),
        IsaOp::Load(RegisterName::new(0), RegisterName::new(0), 32),
        IsaOp::LoadI(RegisterName::new(1), 10, 32),
        IsaOp::CmpGt(
            RegisterName::new(0),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        IsaOp::BindReadOnly(RegisterName::new(2), 2, encrypted),
        IsaOp::Load(RegisterName::new(1), RegisterName::new(2), 32),
        IsaOp::BindReadOnly(RegisterName::new(1), 1, encrypted),
        IsaOp::Load(RegisterName::new(2), RegisterName::new(1), 32),
        IsaOp::Cmux(
            RegisterName::new(0),
            RegisterName::new(0),
            RegisterName::new(2),
            RegisterName::new(1),
        ),
        IsaOp::BindReadWrite(RegisterName::new(3), 3, encrypted),
        IsaOp::Store(RegisterName::new(3), RegisterName::new(0), 32),
    ]
}

fn can_cmux(encrypted_computation: bool) {
    let (mut proc, enc) = make_computer_80();

    // Make an array of size 10 of random numbers modulo 20
    let random_conditions = (0..10).map(|_| thread_rng().next_u32() % 20);

    for bound in random_conditions {
        let a = thread_rng().next_u32();
        let b = thread_rng().next_u32();

        let expected = if bound > 10 { a } else { b };

        let buffer_0 = buffer_from_value_80(bound, &enc, encrypted_computation);
        let buffer_1 = buffer_from_value_80(a, &enc, encrypted_computation);
        let buffer_2 = buffer_from_value_80(b, &enc, encrypted_computation);
        let output_buffer = buffer_from_value_80(0u32, &enc, encrypted_computation);

        let instrutions = cmux_test_program(encrypted_computation);

        let program = FheProgram::from_instructions(instrutions.to_vec());

        let params = vec![buffer_0, buffer_1, buffer_2, output_buffer];

        proc.run_program(&program, &params, 300_000).unwrap();

        let ans: u32 = read_result(&params[3], &enc, encrypted_computation);
        assert_eq!(expected, ans);
    }
}

#[test]
fn can_cmux_plaintext() {
    can_cmux(false);
}

#[test]
fn can_cmux_ciphertext() {
    can_cmux(true);
}
