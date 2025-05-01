use std::sync::Arc;

use crate::{
    ArgsBuilder, Memory, proc::IsaOp, test_utils::make_computer_80,
    tomasulo::registers::RegisterName,
};

#[test]
fn can_neg_plaintext_inputs() {
    let (mut proc, _enc) = make_computer_80();

    let val1 = 14u8;
    let expected = val1.wrapping_neg();

    let memory = Arc::new(Memory::new_default_stack());

    let args = ArgsBuilder::new().arg(val1).return_value::<u8>();

    let program = memory.allocate_program(&[
        IsaOp::Neg(RegisterName::new(10), RegisterName::new(10)),
        IsaOp::Ret(),
    ]);

    let (_, ans) = proc.run_program(program, &memory, args, 100).unwrap();

    assert_eq!(expected, ans);
}
