use std::sync::Arc;

use crate::{
    ArgsBuilder, IsaOp, Memory,
    register_names::{RP, SP, T0, T1, T2, T3},
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
fn async_faulting_instruction() {
    let (mut proc, enc) = make_computer_128();
    let sk = get_secret_keys_128();

    let memory = Memory::new_default_stack();
    let program = memory.allocate_program(&[
        IsaOp::Load(T0, SP, 32, 0),
        IsaOp::Load(T1, SP, 32, 4),
        IsaOp::Add(T2, T0, T1),   // Kick this add off so it's in-flight.
        IsaOp::Trunc(T0, T0, 16), // Truncate T0 to 16-bit because...
        // ...adding a 16 and 32-bit value is illegal. This instruction is async due to T2 dependency.
        IsaOp::Add(T3, T0, T2),
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
fn async_and_sync_faulting_instruction() {
    let (mut proc, enc) = make_computer_128();
    let sk = get_secret_keys_128();

    let memory = Memory::new_default_stack();
    let program = memory.allocate_program(&[
        IsaOp::Load(T0, SP, 32, 0),
        IsaOp::Load(T1, SP, 32, 4),
        IsaOp::Add(T2, T0, T1),   // Kick this add off so it's in-flight.
        IsaOp::Trunc(T0, T0, 16), // Truncate T0 to 16-bit because...
        // ...adding a 16 and 32-bit value is illegal. Instruction is async due to T2.
        IsaOp::Add(T3, T0, T2),
        // ...adding a 16 and 32-bit value is illegal. Instruction's deps are ready.
        IsaOp::Add(T3, T0, T1),
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
