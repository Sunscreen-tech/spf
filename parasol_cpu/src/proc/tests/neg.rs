use crate::{
    proc::IsaOp,
    proc::{Buffer, program::FheProgram},
    test_utils::make_computer_80,
    tomasulo::registers::RegisterName,
};

#[test]
fn can_neg_plaintext_inputs() {
    let (mut proc, _enc) = make_computer_80();

    let val1 = 14u8;
    let expected = val1.wrapping_neg();

    let buffer_0 = Buffer::plain_from_value(&val1);
    let output_buffer = Buffer::plain_from_value(&0u8);

    let program = FheProgram::from_instructions(vec![
        IsaOp::BindReadOnly(RegisterName::new(0), 0, false),
        IsaOp::BindReadWrite(RegisterName::new(1), 1, false),
        IsaOp::Load(RegisterName::new(0), RegisterName::new(0), 8),
        IsaOp::Neg(RegisterName::new(1), RegisterName::new(0)),
        IsaOp::Store(RegisterName::new(1), RegisterName::new(1), 8),
    ]);

    let params = vec![buffer_0, output_buffer];

    proc.run_program(&program, &params, 100).unwrap();

    let ans = params[1].plain_try_into_value::<u8>().unwrap();
    assert_eq!(expected, ans);
}
