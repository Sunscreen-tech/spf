use std::sync::Arc;

use rand::{RngCore, thread_rng};

use crate::{
    ArgsBuilder, Memory, proc::IsaOp, register_names::*, test_utils::make_computer_80,
    tomasulo::registers::RegisterName,
};

use parasol_runtime::{fluent::UInt, test_utils::get_secret_keys_80};

#[test]
fn can_or_plaintext_inputs() {
    let (mut proc, _enc) = make_computer_80();

    let val1 = 14u32;
    let val2 = 7u32;
    let expected = val1 | val2;

    let memory = Arc::new(Memory::new_default_stack());

    let program = memory.allocate_program(&[IsaOp::Or(A0, A0, A1), IsaOp::Ret()]);

    let args = ArgsBuilder::new().arg(val1).arg(val2).return_value::<u32>();

    let (_, ans) = proc.run_program(program, &memory, args, 100).unwrap();

    assert_eq!(expected, ans);
}

#[test]
fn can_or_ciphertext_inputs() {
    let (mut proc, enc) = make_computer_80();
    let sk = get_secret_keys_80();

    let mut test = |val1: u8, val2: u8| {
        let expected = val1 | val2;

        let memory = Arc::new(Memory::new_default_stack());

        let program = memory.allocate_program(&[IsaOp::Or(A0, A0, A1), IsaOp::Ret()]);

        let args = ArgsBuilder::new()
            .arg(UInt::<8, _>::encrypt_secret(val1 as u64, &enc, &sk))
            .arg(UInt::<8, _>::encrypt_secret(val2 as u64, &enc, &sk))
            .return_value::<UInt<8, _>>();

        let (_, answer) = proc.run_program(program, &memory, args, 200_000).unwrap();

        let answer = answer.decrypt(&enc, &sk) as u8;

        assert_eq!(expected, answer);
    };

    for _ in 0..=10 {
        let val1 = (thread_rng().next_u64() % 16) as u8;
        let val2 = (thread_rng().next_u64() % 16) as u8;
        test(val1, val2);
    }
}
