use std::sync::Arc;

use crate::{
    ArgsBuilder, Memory, proc::IsaOp, registers::*, test_utils::make_computer_80,
    tomasulo::registers::RegisterName,
};

#[test]
fn can_branch_zero() {
    let (mut proc, _enc) = make_computer_80();

    let args = ArgsBuilder::new()
        .arg(0u32)
        .arg(1u32)
        .arg(5u32)
        .return_value::<u32>();

    let memory = Memory::new_default_stack();

    // Equivalent program:
    // let a = 0;
    // let b = 1;
    // let c = 5;
    // loop {
    //     a += b;
    //     if a == c {
    //         break;
    //     }
    // }
    // a
    let program = memory.allocate_program(&[
        IsaOp::Add(A0, A0, A1),
        // Have we hit RegisterName::named(2)?
        IsaOp::CmpEq(T0, A0, A2),
        IsaOp::BranchZero(T0, -16),
        IsaOp::Ret(),
    ]);

    let (_, ans) = proc
        .run_program(program, &Arc::new(memory), args, 200_000)
        .unwrap();

    assert_eq!(5, ans);
}

#[test]
fn can_branch_nonzero() {
    let (mut proc, _enc) = make_computer_80();

    let args = ArgsBuilder::new().arg(5u32).arg(1u32).return_value::<u32>();

    let memory = Memory::new_default_stack();

    // Equivalent program:
    // let a = 5;
    // let b = 1;
    // loop {
    //     a -= b;
    //     if a == 0 {
    //         break;
    //     }
    // }
    // a
    let program = memory.allocate_program(&[
        IsaOp::Sub(A0, A0, A1),
        IsaOp::BranchNonZero(A0, -8),
        IsaOp::Ret(),
    ]);

    let (_, ans) = proc
        .run_program(program, &Arc::new(memory), args, 200_000)
        .unwrap();

    assert_eq!(0, ans);
}
