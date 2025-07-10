use std::sync::Arc;

use crate::{
    ArgsBuilder, IsaOp, Memory,
    register_names::{RP, SP, T0, T1, T2},
    test_utils::make_computer_128,
};
use parasol_runtime::{fluent::UInt32, test_utils::get_secret_keys_128};

#[test]
fn fault_while_instruction_in_flight() {
    let (mut proc, enc) = make_computer_128();
    let sk = get_secret_keys_128();

    let memory = Memory::new_default_stack();
    let program = memory.allocate_program(&[
        IsaOp::Load(T0, SP, 32, 0),
        IsaOp::Load(T1, SP, 32, 4),
        IsaOp::Add(T2, T0, T1),   // Kick this add off so it's in-flight.
        IsaOp::Trunc(T0, T0, 16), // Truncate T0 to 16-bit because...
        IsaOp::Add(T0, T0, T1),   // ...adding a 16 and 32-bit value is illegal.
        IsaOp::Store(RP, T2, 32, 0),
        IsaOp::Ret(),
    ]);

    let args = ArgsBuilder::new()
        .arg(UInt32::encrypt_secret(42, &enc, &sk))
        .arg(UInt32::encrypt_secret(25, &enc, &sk))
        .return_value::<UInt32>();

    let result = proc.run_program(program, &Arc::new(memory), args);

    assert!(result.is_err());
}

#[test]
fn fault_while_two_instructions_in_flight() {
    let (mut proc, enc) = make_computer_128();
    let sk = get_secret_keys_128();

    let memory = Memory::new_default_stack();
    let program = memory.allocate_program(&[
        IsaOp::Load(T0, SP, 32, 0),
        IsaOp::Load(T1, SP, 32, 4),
        IsaOp::Add(T2, T0, T1),   // Kick this add off so it's in-flight.
        IsaOp::Add(T2, T0, T1),   // Kick this add off so it's in-flight.
        IsaOp::Trunc(T0, T0, 16), // Truncate T0 to 16-bit because...
        IsaOp::Add(T0, T0, T1),   // ...adding a 16 and 32-bit value is illegal.
        IsaOp::Store(RP, T2, 32, 0),
        IsaOp::Ret(),
    ]);

    let args = ArgsBuilder::new()
        .arg(UInt32::encrypt_secret(42, &enc, &sk))
        .arg(UInt32::encrypt_secret(25, &enc, &sk))
        .return_value::<UInt32>();

    let result = proc.run_program(program, &Arc::new(memory), args);

    assert!(result.is_err());
}

#[test]
fn two_faulting_instructions() {
    let (mut proc, enc) = make_computer_128();
    let sk = get_secret_keys_128();

    let memory = Memory::new_default_stack();
    let program = memory.allocate_program(&[
        IsaOp::Load(T0, SP, 32, 0),
        IsaOp::Load(T1, SP, 32, 4),
        IsaOp::Add(T2, T0, T1),   // Kick this add off so it's in-flight.
        IsaOp::Trunc(T0, T0, 16), // Truncate T0 to 16-bit because...
        IsaOp::Add(T0, T0, T1),   // ...adding a 16 and 32-bit value is illegal.
        IsaOp::Add(T0, T0, T1),   // ...adding a 16 and 32-bit value is illegal.
        IsaOp::Store(RP, T2, 32, 0),
        IsaOp::Ret(),
    ]);

    let args = ArgsBuilder::new()
        .arg(UInt32::encrypt_secret(42, &enc, &sk))
        .arg(UInt32::encrypt_secret(25, &enc, &sk))
        .return_value::<UInt32>();

    let result = proc.run_program(program, &Arc::new(memory), args);

    assert!(result.is_err());
}
