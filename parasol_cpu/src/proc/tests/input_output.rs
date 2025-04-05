use crate::{
    proc::IsaOp,
    proc::{program::FheProgram, Buffer},
    test_utils::make_computer_80,
    tomasulo::registers::RegisterName,
    Error,
};

use parasol_runtime::test_utils::get_secret_keys_80;

#[test]
fn can_assign_inputs() {
    let (mut proc, enc) = make_computer_80();

    let buffer_0 = Buffer::plain_from_value(&16);
    let buffer_1 = Buffer::cipher_from_value(&16, &enc, &get_secret_keys_80());

    let program = FheProgram::from_instructions(vec![
        IsaOp::BindReadOnly(RegisterName::named(0), 0, false),
        IsaOp::BindReadOnly(RegisterName::named(1), 1, true),
    ]);

    let params = vec![buffer_0, buffer_1];

    proc.run_program(&program, &params).unwrap();
}

#[test]
fn can_assign_outputs() {
    let (mut proc, enc) = make_computer_80();

    let buffer_0 = Buffer::plain_from_value(&16);
    let buffer_1 = Buffer::cipher_from_value(&16, &enc, &get_secret_keys_80());

    let program = FheProgram::from_instructions(vec![
        IsaOp::BindReadWrite(RegisterName::named(0), 0, false),
        IsaOp::BindReadWrite(RegisterName::named(1), 1, true),
    ]);

    let params = vec![buffer_0, buffer_1];

    proc.run_program(&program, &params).unwrap();
}

#[test]
fn cant_alias_inputs() {
    let (mut proc, enc) = make_computer_80();

    let buffer_0 = Buffer::plain_from_value(&7u32);
    let buffer_1 = Buffer::cipher_from_value(&8u32, &enc, &get_secret_keys_80());

    let program = FheProgram::from_instructions(vec![
        IsaOp::BindReadOnly(RegisterName::named(0), 0, false),
        IsaOp::BindReadOnly(RegisterName::named(1), 0, false),
    ]);

    let params = vec![buffer_0, buffer_1];

    let result = proc.run_program(&program, &params);

    assert_eq!(
        result.err().unwrap(),
        Error::AliasingViolation {
            inst_id: 1,
            pc: 1,
            buffer_id: 0
        }
    );
}

#[test]
fn cant_alias_outputs() {
    let (mut proc, enc) = make_computer_80();

    let buffer_0 = Buffer::plain_from_value(&16);
    let buffer_1 = Buffer::cipher_from_value(&16, &enc, &get_secret_keys_80());

    let program = FheProgram::from_instructions(vec![
        IsaOp::BindReadOnly(RegisterName::named(0), 0, false),
        IsaOp::BindReadOnly(RegisterName::named(1), 0, false),
    ]);

    let params = vec![buffer_0, buffer_1];

    let result = proc.run_program(&program, &params);

    assert_eq!(
        result.err().unwrap(),
        Error::AliasingViolation {
            inst_id: 1,
            pc: 1,
            buffer_id: 0
        }
    );
}

#[test]
fn input_ptr_register_pt_ct_mismatch() {
    let (mut proc, _) = make_computer_80();

    let buffer_0 = Buffer::plain_from_value(&16);

    let program =
        FheProgram::from_instructions(vec![IsaOp::BindReadOnly(RegisterName::named(0), 0, true)]);

    let params = vec![buffer_0];

    let result = proc.run_program(&program, &params);

    assert_eq!(
        result.err().unwrap(),
        Error::BufferMismatch { inst_id: 0, pc: 0 }
    );
}

#[test]
fn output_ptr_register_pt_ct_mismatch() {
    let (mut proc, _) = make_computer_80();

    let buffer_0 = Buffer::plain_from_value(&16);

    let program =
        FheProgram::from_instructions(vec![IsaOp::BindReadWrite(RegisterName::named(0), 0, true)]);

    let params = vec![buffer_0];

    let result = proc.run_program(&program, &params);

    assert_eq!(
        result.err().unwrap(),
        Error::BufferMismatch { inst_id: 0, pc: 0 }
    );
}

#[test]
fn missing_input() {
    let (mut proc, _) = make_computer_80();

    let program =
        FheProgram::from_instructions(vec![IsaOp::BindReadOnly(RegisterName::named(0), 0, true)]);

    let result = proc.run_program(&program, &[]);

    assert_eq!(result.err().unwrap(), Error::NoBuffer { inst_id: 0, pc: 0 });
}

#[test]
fn missing_output() {
    let (mut proc, _) = make_computer_80();

    let program =
        FheProgram::from_instructions(vec![IsaOp::BindReadWrite(RegisterName::named(0), 0, true)]);

    let result = proc.run_program(&program, &[]);

    assert_eq!(result.err().unwrap(), Error::NoBuffer { inst_id: 0, pc: 0 });
}
