use std::sync::Arc;

use crate::{ArgsBuilder, Memory, proc::IsaOp, register_names::*, test_utils::make_computer_128};

#[test]
fn can_neg_plaintext_inputs() {
    let (mut proc, _enc) = make_computer_128();

    let val1 = 14u8;
    let expected = val1.wrapping_neg();

    let memory = Arc::new(Memory::new_default_stack());

    let args = ArgsBuilder::new().arg(val1).return_value::<u8>();

    let program = memory.allocate_program(&[
        IsaOp::Load(T0, SP, 8, 0),
        IsaOp::Neg(T0, T0),
        IsaOp::Store(A0, T0, 8, 0),
        IsaOp::Ret(),
    ]);

    let ans = proc.run_program(program, &memory, args).unwrap();

    assert_eq!(expected, ans);
}
