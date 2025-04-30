use std::sync::Arc;

use crate::{
    ArgsBuilder, IsaOp, Memory, test_utils::make_computer_80, tomasulo::registers::RegisterName,
};

#[test]
fn unsigned_values_zero_extend_4_byte() {
    let (mut proc, _) = make_computer_80();

    let memory = Arc::new(Memory::new_default_stack());

    let program = memory.allocate_program(&[IsaOp::Ret()]);

    let args = ArgsBuilder::new().arg(0x80u8).return_value::<u32>();
    let result = proc.run_program(program, &memory, args, 200_000).unwrap();

    assert_eq!(result, 0x0000_0080u32);

    let args = ArgsBuilder::new().arg(0x8000u16).return_value::<u32>();
    let result = proc.run_program(program, &memory, args, 200_000).unwrap();

    assert_eq!(result, 0x0000_8000u32);
}

#[test]
fn signed_values_sign_extend_4_byte() {
    let (mut proc, _) = make_computer_80();

    let memory = Arc::new(Memory::new_default_stack());

    let program = memory.allocate_program(&[IsaOp::Ret()]);

    let args = ArgsBuilder::new().arg(i8::MIN).return_value::<i32>();
    let result = proc.run_program(program, &memory, args, 200_000).unwrap();

    assert_eq!(result, i8::MIN as i32);

    let args = ArgsBuilder::new().arg(i16::MIN).return_value::<i32>();
    let result = proc.run_program(program, &memory, args, 200_000).unwrap();

    assert_eq!(result, i16::MIN as i32);
}

#[test]
fn eight_byte_vals_2_registers() {
    let (mut proc, _) = make_computer_80();

    let memory = Arc::new(Memory::new_default_stack());

    // value should get passed in r10+r11 and returned in r10+r11.
    let program = memory.allocate_program(&[IsaOp::Ret()]);

    let args = ArgsBuilder::new()
        .arg(0xDEADBEEF_FEEDF00Du64)
        .return_value::<u64>();
    let result = proc.run_program(program, &memory, args, 200_000).unwrap();

    assert_eq!(result, 0xDEADBEEF_FEEDF00Du64);
}

#[test]
fn eight_4_byte_args() {
    let (mut proc, _) = make_computer_80();

    let memory = Arc::new(Memory::new_default_stack());

    // Args should be passed in r10-r17. Sum and return in r10.
    let program = memory.allocate_program(&[
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(11),
            RegisterName::new(10),
        ),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(12),
            RegisterName::new(10),
        ),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(13),
            RegisterName::new(10),
        ),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(14),
            RegisterName::new(10),
        ),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(15),
            RegisterName::new(10),
        ),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(16),
            RegisterName::new(10),
        ),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(17),
            RegisterName::new(10),
        ),
        IsaOp::Ret(),
    ]);

    let args = ArgsBuilder::new()
        .arg(1u32)
        .arg(1u32)
        .arg(1u32)
        .arg(1u32)
        .arg(1u32)
        .arg(1u32)
        .arg(1u32)
        .arg(1u32)
        .return_value::<u32>();
    let result = proc.run_program(program, &memory, args, 200_000).unwrap();

    assert_eq!(result, 8);
}

#[test]
fn four_8_byte_args() {
    let (mut proc, _) = make_computer_80();

    let memory = Arc::new(Memory::new_default_stack());

    // Args should be passed in r10-r17 in 2-word pairs. Odd registers will
    // be hi words, and thus zero. Sum and return in r10.
    let program = memory.allocate_program(&[
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(11),
            RegisterName::new(10),
        ),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(12),
            RegisterName::new(10),
        ),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(13),
            RegisterName::new(10),
        ),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(14),
            RegisterName::new(10),
        ),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(15),
            RegisterName::new(10),
        ),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(16),
            RegisterName::new(10),
        ),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(17),
            RegisterName::new(10),
        ),
        IsaOp::Ret(),
    ]);

    let args = ArgsBuilder::new()
        .arg(1u64)
        .arg(1u64)
        .arg(1u64)
        .arg(1u64)
        .return_value::<u32>();
    let result = proc.run_program(program, &memory, args, 200_000).unwrap();

    assert_eq!(result, 4);
}

#[test]
fn large_return_value() {
    let (mut proc, _) = make_computer_80();

    let memory = Arc::new(Memory::new_default_stack());

    let program = memory.allocate_program(&[
        IsaOp::LoadI(RegisterName::new(5), 0xDEADBEEF, 32),
        IsaOp::LoadI(RegisterName::new(6), 0xFEEDF00D, 32),
        IsaOp::LoadI(RegisterName::new(7), 4, 32),
        IsaOp::Store(RegisterName::new(10), RegisterName::new(5), 4),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(10),
            RegisterName::new(7),
        ),
        IsaOp::Store(RegisterName::new(10), RegisterName::new(6), 4),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(10),
            RegisterName::new(7),
        ),
        IsaOp::Store(RegisterName::new(10), RegisterName::new(6), 4),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(10),
            RegisterName::new(7),
        ),
        IsaOp::Store(RegisterName::new(10), RegisterName::new(5), 4),
        IsaOp::Ret(),
    ]);

    let args = ArgsBuilder::new().return_value::<[u32; 4]>();

    let ans = proc.run_program(program, &memory, args, 200_000).unwrap();

    assert_eq!(ans[0], 0xDEADBEEF);
    assert_eq!(ans[1], 0xFEEDF00D);
    assert_eq!(ans[2], 0xFEEDF00D);
    assert_eq!(ans[3], 0xDEADBEEF);
}

#[test]
fn two_large_parameters() {
    let (mut proc, _) = make_computer_80();
    let x = std::array::from_fn::<_, 16, _>(|x| x as u8);
    let y = x.map(|x| x << 4);

    let memory = Arc::new(Memory::new_default_stack());

    // Parameters should be passed by reference in x10, x11. Offset by 12 bytes and
    // load 4 bytes from each and or them together.
    let program = memory.allocate_program(&[
        IsaOp::LoadI(RegisterName::new(7), 12, 32),
        IsaOp::Add(
            RegisterName::new(10),
            RegisterName::new(10),
            RegisterName::new(7),
        ),
        IsaOp::Load(RegisterName::new(10), RegisterName::new(10), 4),
        IsaOp::Add(
            RegisterName::new(11),
            RegisterName::new(11),
            RegisterName::new(7),
        ),
        IsaOp::Load(RegisterName::new(11), RegisterName::new(11), 4),
        IsaOp::Or(
            RegisterName::new(10),
            RegisterName::new(10),
            RegisterName::new(11),
        ),
        IsaOp::Ret(),
    ]);

    let args = ArgsBuilder::new().arg(x).arg(y).return_value::<u32>();

    let result = proc.run_program(program, &memory, args, 200_000).unwrap();

    assert_eq!(result, 0xFFEEDDCC);
}

#[test]
fn pass_on_stack_wide() {
    let (mut proc, _) = make_computer_80();

    let memory = Arc::new(Memory::new_default_stack());

    // Overflow our 8 registers to force the last argument onto the stack.
    let args = ArgsBuilder::new()
        .arg(0u64)
        .arg(0u64)
        .arg(0u64)
        .arg(0u64)
        .arg(0xDEADBEEF_FEEDF00Du64)
        .return_value::<u64>();

    // Read the 8 bytes off the stack pointer
    let program = memory.allocate_program(&[
        IsaOp::LoadI(RegisterName::new(7), 4, 32),
        IsaOp::Load(RegisterName::new(10), RegisterName::new(2), 4),
        IsaOp::Add(
            RegisterName::new(8),
            RegisterName::new(2),
            RegisterName::new(7),
        ),
        IsaOp::Load(RegisterName::new(11), RegisterName::new(8), 4),
        IsaOp::Ret(),
    ]);

    let result = proc.run_program(program, &memory, args, 200_000).unwrap();

    assert_eq!(result, 0xDEADBEEF_FEEDF00Du64);
}
