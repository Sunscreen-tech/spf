use crate::{
    proc::IsaOp,
    proc::{Buffer, program::FheProgram},
    test_utils::make_computer_80,
    tomasulo::registers::RegisterName,
};

#[test]
fn can_branch_zero() {
    let (mut proc, _enc) = make_computer_80();

    let output_buffer = Buffer::plain_from_value(&0u32);

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
    let program = FheProgram::from_instructions(vec![
        IsaOp::LoadI(RegisterName::new(0), 0, 32),
        IsaOp::LoadI(RegisterName::new(1), 1, 32),
        IsaOp::LoadI(RegisterName::new(2), 5, 32),
        IsaOp::BindReadWrite(RegisterName::new(3), 0, false),
        IsaOp::Add(
            RegisterName::new(0),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        // Have we hit RegisterName::named(2)?
        IsaOp::CmpEq(
            RegisterName::new(4),
            RegisterName::new(0),
            RegisterName::new(2),
        ),
        IsaOp::BranchZero(RegisterName::new(4), 4),
        IsaOp::Store(RegisterName::new(3), RegisterName::new(0), 32),
    ]);

    let params = vec![output_buffer];

    proc.run_program(&program, &params, 100).unwrap();

    let ans = params[0].plain_try_into_value::<u32>().unwrap();
    assert_eq!(5, ans);
}

#[test]
fn can_branch_nonzero() {
    let (mut proc, _enc) = make_computer_80();

    let output_buffer = Buffer::plain_from_value(&0u32);

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
    let program = FheProgram::from_instructions(vec![
        IsaOp::LoadI(RegisterName::new(0), 5, 32),
        IsaOp::LoadI(RegisterName::new(1), 1, 32),
        IsaOp::BindReadWrite(RegisterName::new(3), 0, false),
        IsaOp::Sub(
            RegisterName::new(0),
            RegisterName::new(0),
            RegisterName::new(1),
        ),
        IsaOp::BranchNonZero(RegisterName::new(0), 3),
        IsaOp::Store(RegisterName::new(3), RegisterName::new(0), 32),
    ]);

    let params = vec![output_buffer];

    proc.run_program(&program, &params, 100).unwrap();

    let ans = params[0].plain_try_into_value::<u32>().unwrap();
    assert_eq!(0, ans);
}
