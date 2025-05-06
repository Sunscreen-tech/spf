use std::sync::Arc;

use rand::{RngCore, thread_rng};

use crate::{
    ArgsBuilder, Memory,
    proc::IsaOp,
    register_names::*,
    test_utils::{MaybeEncryptedUInt, make_computer_80},
    tomasulo::registers::RegisterName,
};

use parasol_runtime::test_utils::get_secret_keys_80;

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
fn cmux_test_program() -> Vec<IsaOp> {
    vec![
        IsaOp::LoadI(T0, 10, 32),
        IsaOp::CmpGt(T0, A0, T0),
        IsaOp::Cmux(A0, T0, A1, A2),
        IsaOp::Ret(),
    ]
}

fn can_cmux(encrypted_computation: bool) {
    let (mut proc, enc) = make_computer_80();
    let sk = get_secret_keys_80();

    // Make an array of size 10 of random numbers modulo 20
    let random_conditions = (0..10).map(|_| thread_rng().next_u32() % 20);

    for bound in random_conditions {
        let a = thread_rng().next_u32();
        let b = thread_rng().next_u32();

        let expected = if bound > 10 { a } else { b };

        let memory = Arc::new(Memory::new_default_stack());

        let args = ArgsBuilder::new()
            .arg(MaybeEncryptedUInt::<32>::new(
                bound as u64,
                &enc,
                &sk,
                encrypted_computation,
            ))
            .arg(MaybeEncryptedUInt::<32>::new(
                a as u64,
                &enc,
                &sk,
                encrypted_computation,
            ))
            .arg(MaybeEncryptedUInt::<32>::new(
                b as u64,
                &enc,
                &sk,
                encrypted_computation,
            ))
            .return_value::<MaybeEncryptedUInt<32>>();

        let program = memory.allocate_program(&cmux_test_program());

        let (_, ans) = proc.run_program(program, &memory, args, 200_000).unwrap();

        assert_eq!(expected, ans.get(&enc, &sk));
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
