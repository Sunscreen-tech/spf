use std::sync::Arc;

use crate::{ArgsBuilder, Memory, proc::IsaOp, register_names::*, test_utils::make_computer_128};

#[test]
fn can_branch_zero() {
    let (mut proc, _enc) = make_computer_128();

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
        IsaOp::Load(T0, SP, 32, 0),
        IsaOp::Load(T1, SP, 32, 4),
        IsaOp::Load(T2, SP, 32, 8),
        IsaOp::Add(T0, T0, T1),
        // Have we hit A2?
        IsaOp::CmpEq(T3, T0, T2),
        IsaOp::BranchZero(T3, -16),
        IsaOp::Store(A0, T0, 32, 0),
        IsaOp::Ret(),
    ]);

    let ans = proc.run_program(program, &Arc::new(memory), args).unwrap();

    assert_eq!(5, ans);
}

#[test]
fn can_branch_nonzero() {
    let (mut proc, _enc) = make_computer_128();

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
        IsaOp::Load(T0, SP, 32, 0),
        IsaOp::Load(T1, SP, 32, 4),
        IsaOp::Sub(T0, T0, T1),
        IsaOp::BranchNonZero(T0, -8),
        IsaOp::Store(A0, T0, 32, 0),
        IsaOp::Ret(),
    ]);

    let ans = proc.run_program(program, &Arc::new(memory), args).unwrap();

    assert_eq!(0, ans);
}

#[test]
fn can_unconditional_branch() {
    let (mut proc, _enc) = make_computer_128();

    let args = ArgsBuilder::new().arg(5u32).arg(1u32).return_value::<u32>();

    let memory = Memory::new_default_stack();

    // Equivalent program:
    // int x = 42;
    // goto END;
    // x = 0;
    // END:
    // return x;
    let program = memory.allocate_program(&[
        IsaOp::LoadI(T0, 42, 32),
        IsaOp::Branch(16), // Skip next instruction
        IsaOp::LoadI(T0, 0, 32),
        IsaOp::Store(A0, T0, 32, 0),
        IsaOp::Ret(),
    ]);

    let ans = proc.run_program(program, &Arc::new(memory), args).unwrap();

    assert_eq!(42, ans);
}
